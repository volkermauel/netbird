package api

// TopologyNode represents a node in a network topology graph.
type TopologyNode struct {
	Id    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"`
}

// TopologyEdge represents a connection between two nodes.
type TopologyEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
}

// NetworkTopology represents a graph of network elements and their relations.
type NetworkTopology struct {
	Nodes []TopologyNode `json:"nodes"`
	Edges []TopologyEdge `json:"edges"`
}
