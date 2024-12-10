from flask import Flask, jsonify, request, send_from_directory
import psutil
from flask_cors import CORS
from threading import Thread, Event
from scapy.all import sniff, wrpcap, IP, IPv6, ARP
import time
import os
import pyodbc

app = Flask(__name__)
CORS(app)

# Global variables
capture_thread = None
capture_active = Event()
captured_packets = []
selected_interface = None
pcap_file_path = 'captured_packets.pcap'
saved_sessions = []

db_connection_string = 'DRIVER={ODBC Driver 17 for SQL Server};SERVER=localhost\\SQLEXPRESS;DATABASE=K9Data;Trusted_Connection=yes;'

# Create a database connection
def get_db_connection():
    return pyodbc.connect(db_connection_string)

# Capture packets function
def packet_callback(packet):
    packet_details = {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()),
        "data": packet.summary(),
        "source_ip": None,
        "destination_ip": None,
        "protocol": None,
        "length": len(packet)
    }
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        packet_details['source_ip'] = ip_layer.src
        packet_details['destination_ip'] = ip_layer.dst
        if ip_layer.proto == 6:
            packet_details['protocol'] = 'TCP'
        elif ip_layer.proto == 17:
            packet_details['protocol'] = 'UDP'
        elif ip_layer.proto == 1:
            packet_details['protocol'] = 'ICMP'
        else:
            packet_details['protocol'] = 'Other'
    elif packet.haslayer(IPv6):
        ipv6_layer = packet[IPv6]
        packet_details['source_ip'] = ipv6_layer.src
        packet_details['destination_ip'] = ipv6_layer.dst
        if ipv6_layer.proto == 6:
            packet_details['protocol'] = 'TCP'
        elif ipv6_layer.proto == 17:
            packet_details['protocol'] = 'UDP'
        elif ipv6_layer.proto == 58:
            packet_details['protocol'] = 'ICMPv6'
        else:
            packet_details['protocol'] = 'Other'
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        packet_details['source_ip'] = arp_layer.psrc
        packet_details['destination_ip'] = arp_layer.pdst
        packet_details['protocol'] = 'ARP'

    captured_packets.append(packet_details)  # Add packet to captured list

# Capture packets function
def capture_packets(interface):
    while capture_active.is_set():
        sniff(prn=packet_callback, store=False, timeout=1, iface=interface)

# Start capture endpoint
@app.route('/start', methods=['POST'])
def start_capture():
    global capture_thread, selected_interface
    data = request.get_json()
    selected_interface = data.get('interface')

    if not selected_interface:
        return jsonify({"message": "Interface not specified"}), 400

    if not capture_active.is_set():
        capture_active.set()
        captured_packets.clear()
        capture_thread = Thread(target=capture_packets, args=(selected_interface,))
        capture_thread.start()
        return jsonify({"message": f"Capture started on {selected_interface}"}), 200
    return jsonify({"message": "Capture already running"}), 400

# Stop capture endpoint
@app.route('/stop', methods=['POST'])
def stop_capture():
    capture_active.clear()
    if capture_thread and capture_thread.is_alive():
        capture_thread.join()
    return jsonify({"message": "Capture stopped"}), 200

# Resume capture endpoint
@app.route('/resume', methods=['POST'])
def resume_capture():
    global capture_thread, selected_interface
    if not capture_active.is_set() and selected_interface:
        capture_active.set()
        capture_thread = Thread(target=capture_packets, args=(selected_interface,))
        capture_thread.start()
        return jsonify({"message": f"Capture resumed on {selected_interface}"}), 200
    return jsonify({"message": "Capture already running"}), 400

@app.route('/download_session', methods=['POST'])
# Save packets to .pcap function
def download_session_path():
    global pcap_file_path
    print("Received request to download session")
    data = request.get_json()
    username = data.get('username')
    session_number = data.get('session_number')
    captured_packets_download = data.get('captured_packets')

    # Item to remove from each packet
    item_to_remove = "data"

    # Loop through each packet in the list and remove the 'timestamp' key
    for packet in captured_packets_download:
        if item_to_remove in packet:
            del packet[item_to_remove]  # Remove the 'timestamp' key


    # Define the pcap file path temporarily
    pcap_file_path = os.path.join('pcap_folder', f"{username}_session{session_number}.pcap")
    try:
        # If captured_packets_download is already in raw Scapy format
        if isinstance(captured_packets_download, list):  # Assuming it's a list of Scapy packets
            # Save packets to a .pcap file using wrpcap
            wrpcap(pcap_file_path, captured_packets_download)
            print(f"Packets saved to {pcap_file_path}")
        else:
            return jsonify({'success': False, 'message': 'Invalid packet data format'})

        # Return the file path to be downloaded
        return send_from_directory("pcap_folder", f"{username}_session{session_number}.pcap", as_attachment=True)

    except Exception as e:
        print(f"Error during capture save: {str(e)}")
        return jsonify({'success': False, 'message': 'Error saving packets to file'})

# Save capture endpoint
@app.route('/save', methods=['POST'])
def save_capture():
    global saved_sessions
    # Get session details from the request
    data = request.get_json()
    username = data.get('username')
    session_date = time.strftime('%Y-%m-%d')  # Get current date
    captured_packets_count = len(captured_packets)

    if not username:
        return jsonify({"message": "Username is required"}), 400

    try:
        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch the latest session number for the user
        cursor.execute("SELECT MAX(SessionNumber) FROM SavedSessions WHERE UserName = ?", (username,))
        latest_session_number = cursor.fetchone()[0] or 0
        session_number = latest_session_number + 1

        # Insert the new session into the database
        cursor.execute("""
            INSERT INTO SavedSessions (SessionDate, UserName, SessionNumber, CapturedPackets)
            VALUES (?, ?, ?, ?)
        """, (session_date, username, session_number, captured_packets_count))
        conn.commit()

        # Retrieve the generated SessionID for the inserted session
        session_id = cursor.execute("SELECT @@IDENTITY").fetchone()[0]

        # Save each packet's details to the CapturedPackets table
        for packet in captured_packets:
            cursor.execute("""
                INSERT INTO CapturedPackets (session_id, timestamp, packet_data, source_ip, destination_ip, protocol, packetlength)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                packet.get('timestamp'),
                packet.get('data'),
                packet.get('source_ip'),
                packet.get('destination_ip'),
                packet.get('protocol'),
                packet.get('length')
            ))
        conn.commit()

        # Append to in-memory saved sessions list for quick retrieval
        saved_sessions.append({
            "username": username,
            "session_date": session_date,
            "session_number": session_number,
            "captured_packets": captured_packets_count,
            "file": pcap_file_path
        })
        if captured_packets_count == 0:
            return jsonify({"message": "No packets captured to save"}), 400

        return jsonify({"message": "Capture saved successfully", "session_number": session_number}), 200

    except Exception as e:
        print(f"Error saving capture: {str(e)}")
        return jsonify({"message": f"Error saving capture: {str(e)}"}), 500

    finally:
        conn.close()

# Retrieve captured packets
@app.route('/packets', methods=['GET'])
def get_packets():
    return jsonify({"packets": captured_packets}), 200

# Endpoint to get network interfaces
@app.route('/interfaces', methods=['GET'])
def get_interfaces():
    interfaces = psutil.net_if_addrs()
    interface_names = list(interfaces.keys())
    return jsonify({"interfaces": interface_names}), 200

# Serve saved sessions endpoint
@app.route('/saved-sessions', methods=['POST'])
def get_saved_sessions():
    print("Fetching saved sessions")
    data = request.get_json()
    username = data.get('username')

    try:
        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch all saved sessions
        cursor.execute("""
            SELECT SessionID, SessionDate, SessionNumber, CapturedPackets 
            FROM SavedSessions 
            WHERE UserName = ? 
        """, (username,))
        
        sessions = cursor.fetchall()
        print(sessions)

        # Convert results to JSON-friendly format
        session_list = [
            {
                "session_id": row[0],
                "session_date": row[1],
                "session_number": row[2],
                "captured_packets": row[3]
            }
            for row in sessions
        ]
    
        return jsonify({"success": True, "saved_sessions": session_list}), 200

    except Exception as e:
        print(f"Error fetching saved sessions: {str(e)}")
        return jsonify({"message": f"Error fetching saved sessions: {str(e)}"}), 500

    finally:
        conn.close()

# Retrieve saved sessions packets
@app.route('/saved-packets', methods=['POST'])
def get_saved_packetss():
    data = request.json
    session_id = data.get('session_id')
    print("Fetching saved sessions' packets")
    try:
        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch all packets for the specific session id
        cursor.execute("""
            SELECT timestamp, packet_data, source_ip, destination_ip, protocol, packetlength
            FROM CapturedPackets
            WHERE session_id = ?
        """, (session_id,))
        
        packets = cursor.fetchall()

        # Convert the fetched data to a list of dictionaries
        packet_list = []
        for packet in packets:
            packet_list.append({
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', packet[0].timetuple()),
                "data": packet[1],
                "source_ip": packet[2],
                "destination_ip": packet[3],
                "protocol": packet[4],
                "packetlength": packet[5]
            })

        return jsonify({"success": True,"capturedpackets": packet_list}), 200

    except Exception as e:
        print(f"Error fetching packets: {e}")
        return jsonify({"error": "An error occurred while fetching packets"}), 500

    finally:
        cursor.close()
        conn.close()

@app.route('/delete-session', methods=['POST'])
def delete_session():
    data = request.json
    session_number = data.get('session_number')
    username = data.get('username')

    try:
        # Connect to the database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Delete all packets for the specific session number
        cursor.execute("""
            SELECT session_id FROM SavedSessions WHERE SessionNumber = ? AND UserName = ?
        """, (session_number, username,))

        session_id = cursor.fetchone()
        if session_id:
            session_id = session_id[0]
        else:
            return jsonify({'success': False, 'message': 'Session not found for current user: {username}'}), 404


        cursor.execute("""
            DELETE FROM CapturedPackets WHERE session_id = ?
        """, (session_id,))
        conn.commit()

        cursor.execute("""
            DELETE FROM SavedSessions WHERE session_id = ?
        """, (session_id,))
        conn.commit()
        
    except ValueError as ve:
        print(f"Validation error: {ve}")
    except Exception as ex:
        print(f"Unexpected error: {ex}")
    finally:
        if conn:
            conn.close()
            
    return jsonify({'success': True, 'message': 'Session deleted successfully'}), 200

# Serve pcap file for download
@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        # Send the file from the current directory
        return send_from_directory(directory=os.getcwd(), path=filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({"message": "File not found"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

