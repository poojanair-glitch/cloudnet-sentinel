import http.server
import socketserver
import os
import json
import webbrowser

PORT = 8000
DIRECTORY = "data"

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            
            html = """
            <!DOCTYPE html>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial, sans-serif; background-color: #f4f4f9; margin: 0; padding: 20px; }
                h1 { text-align: center; color: #333; }
                svg { width: 100%; height: 80vh; background-color: white; border: 1px solid #ccc; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
                .node text { pointer-events: none; font-size: 12px; }
                .link { fill: none; stroke: #999; stroke-width: 2px; }
                .link.attack_path { stroke: #d9534f; stroke-width: 3px; }
                .node.compromised circle { fill: #d9534f; stroke: #d43f3a; stroke-width: 2px; }
            </style>
            <body>
            <h1>CloudNet Sentinel Attack Graph</h1>
            <svg id="graph"></svg>
            <script src="https://d3js.org/d3.v6.min.js"></script>
            <script>
                d3.json("/graph_viz.json").then(function(data) {
                    const width = document.querySelector('svg').clientWidth;
                    const height = document.querySelector('svg').clientHeight;

                    const svg = d3.select("#graph")
                        .attr("width", width)
                        .attr("height", height);

                    const simulation = d3.forceSimulation(data.nodes)
                        .force("link", d3.forceLink(data.links).id(d => d.id).distance(150))
                        .force("charge", d3.forceManyBody().strength(-400))
                        .force("center", d3.forceCenter(width / 2, height / 2));

                    const link = svg.append("g")
                        .selectAll("line")
                        .data(data.links)
                        .join("line")
                        .attr("class", d => d.is_attack_path ? "link attack_path" : "link");

                    const node = svg.append("g")
                        .selectAll("g")
                        .data(data.nodes)
                        .join("g")
                        .attr("class", d => d.is_compromised ? "node compromised" : "node")
                        .call(d3.drag()
                            .on("start", dragstarted)
                            .on("drag", dragged)
                            .on("end", dragended));

                    node.append("circle")
                        .attr("r", d => 15 + d.sensitivity * 5)
                        .attr("fill", d => d.is_compromised ? "#d9534f" : "#5cb85c");

                    node.append("text")
                        .attr("dx", 20)
                        .attr("dy", ".35em")
                        .text(d => `${d.icon} ${d.label}`);

                    simulation.on("tick", () => {
                        link.attr("x1", d => d.source.x)
                            .attr("y1", d => d.source.y)
                            .attr("x2", d => d.target.x)
                            .attr("y2", d => d.target.y);
                        node.attr("transform", d => `translate(${d.x},${d.y})`);
                    });

                    function dragstarted(event, d) {
                        if (!event.active) simulation.alphaTarget(0.3).restart();
                        d.fx = d.x; d.fy = d.y;
                    }
                    function dragged(event, d) {
                        d.fx = event.x; d.fy = event.y;
                    }
                    function dragended(event, d) {
                        if (!event.active) simulation.alphaTarget(0);
                        d.fx = null; d.fy = null;
                    }
                }).catch(function(error){
                    console.log("Error loading graph_viz.json:", error);
                    d3.select("#graph").append("text").attr("x", 50).attr("y", 50).text("Error loading graph data. Run a scan first.");
                });
            </script>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))
        else:
            super().do_GET()

def start_server():
    os.makedirs(DIRECTORY, exist_ok=True)
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"🌐 Serving at http://localhost:{PORT}")
        print("💡 Press Ctrl+C to stop the server.")
        webbrowser.open(f"http://localhost:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Server stopped.")
