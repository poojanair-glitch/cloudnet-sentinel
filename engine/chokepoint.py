from collections import Counter
import networkx as nx

class ChokePointAnalyzer:
    def __init__(self, G, paths):
        self.G = G
        self.paths = paths

    def identify_strategic_chokepoints(self, top_n=3):
        """
        Analyzes all attack paths to identify the most frequent intermediate nodes.
        These are the 'choke points' - fixing these secures the most paths.
        """
        if not self.paths: return []

        node_counts = Counter()
        path_mapping = {} # Maps node to the paths it belongs to

        for p_idx, p in enumerate(self.paths):
            # Ignore the absolute source (e.g., Internet) and target (e.g., S3 bucket)
            # Focus on the pivoting infrastructure (EC2, IAM)
            intermediate_nodes = p['path'][1:-1]
            for node in intermediate_nodes:
                node_counts[node] += 1
                if node not in path_mapping:
                    path_mapping[node] = []
                path_mapping[node].append(p_idx)

        chokepoints = []
        for node, count in node_counts.most_common(top_n):
            node_data = self.G.nodes.get(node, {})
            
            # Calculate Risk Reduction % (How many paths die if this is fixed?)
            reduction_pct = round((count / len(self.paths)) * 100, 1)
            
            chokepoints.append({
                'id': node,
                'type': node_data.get('type', 'unknown'),
                'name': node_data.get('name', node),
                'paths_intersected': count,
                'risk_reduction_pct': reduction_pct,
                'affected_paths': path_mapping[node]
            })

        return chokepoints
