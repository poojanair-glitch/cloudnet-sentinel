from flask import Flask, render_template, request, redirect, url_for, jsonify, session as flask_session
import boto3
import threading

from scanner.ec2_scanner import scan_ec2
from scanner.iam_scanner import scan_iam
from scanner.s3_scanner import scan_s3
from scanner.sg_scanner import scan_security_groups

from engine.graph_engine import GraphEngine
from engine.attack_path_engine import AttackPathEngine
from engine.explanation_engine import ExplanationEngine
from engine.asset_intelligence_engine import AssetIntelligenceEngine
from engine.cost_engine import CostEngine

from realtime.event_simulator import EventSimulator
from realtime.correlation_engine import CorrelationEngine

app = Flask(__name__)
app.secret_key = 'super-secret-key-cloudnet'

# Global state for simulation (in-memory)
SIMULATION_DATA = {
    "events": [],
    "graph": None,
    "attack_paths": []
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login-screen')
def login_screen():
    return render_template('login.html')

@app.route('/signup-screen')
def signup_screen():
    return render_template('signup.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        return redirect(url_for('login_screen'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        flask_session['aws_ak'] = request.form.get('access_key')
        flask_session['aws_sk'] = request.form.get('secret_key')
        flask_session['region'] = request.form.get('region')
        return redirect(url_for('dashboard'))
    return redirect(url_for('login_screen'))

@app.route('/dashboard')
def dashboard():
    if 'aws_ak' not in flask_session:
        return redirect(url_for('index'))
    
    simulate_iam = request.args.get('simulate_iam') == 'true'
    
    boto_session = boto3.Session(
        aws_access_key_id=flask_session['aws_ak'],
        aws_secret_access_key=flask_session['aws_sk'],
        region_name=flask_session['region']
    )
    
    ec2_client = boto_session.client('ec2')
    scan_results = {
        "ec2": scan_ec2(boto_session),
        "iam": scan_iam(boto_session),
        "s3": scan_s3(boto_session),
        "vpcs": ec2_client.describe_vpcs()['Vpcs'],
        "subnets": ec2_client.describe_subnets()['Subnets'],
        "sgs": scan_security_groups(boto_session)
    }
    
    # Linear Pipeline (Unified Flow)
    ge = GraphEngine()
    graph_obj = ge.build_graph(scan_results, simulation_flags={"simulate_iam": simulate_iam})
    
    ape = AttackPathEngine()
    path_data = ape.find_attack_paths(graph_obj)
    
    ee = ExplanationEngine()
    explanations = ee.generate_explanations(graph_obj, path_data)
    
    ce = CostEngine()
    cost = ce.generate_cost_analysis(boto_session, path_data, graph_obj)

    aie = AssetIntelligenceEngine()
    assets = aie.map_assets_to_attack_graph(graph_obj, scan_results, path_data)
    
    # Save for background sim (store the DiGraph object)
    SIMULATION_DATA["graph"] = graph_obj["graph"]
    SIMULATION_DATA["attack_paths"] = path_data['paths']
    
    # Remove non-serializable DiGraph object before passing to template
    del graph_obj["graph"]
    
    intelligence = {
        "graph": graph_obj,
        "attack_paths": path_data['paths'],
        "reasoning": path_data['reasoning'],
        "explanations": explanations,
        "cost": cost,
        "assets": assets,
        "simulation_active": simulate_iam
    }

    if not any(t.name == "SimulationThread" for t in threading.enumerate()):
        threading.Thread(target=run_simulation, name="SimulationThread", daemon=True).start()

    return render_template('dashboard.html', intelligence=intelligence)

def run_simulation():
    sim = EventSimulator()
    while True:
        if SIMULATION_DATA["graph"]:
            nodes = list(SIMULATION_DATA["graph"].nodes)
            for event in sim.simulate_events(nodes):
                ce = CorrelationEngine(SIMULATION_DATA["attack_paths"])
                correlation = ce.correlate(event)
                SIMULATION_DATA["events"].append(correlation)
                if len(SIMULATION_DATA["events"]) > 20:
                    SIMULATION_DATA["events"].pop(0)

@app.route('/api/events')
def get_events():
    return jsonify(SIMULATION_DATA["events"])

@app.route('/logout')
def logout():
    flask_session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5001)
