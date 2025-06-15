class AnomalousNode:
    def __init__(self, ip=None, recon_error=0.0, mlp_score=0.0, 
                 detected_by="", log_timestamp="", total_nodes_in_graph=0, 
                 source_file="", composite_score = 0.0):
        self._ip = ip
        self._recon_error = recon_error
        self._mlp_score = mlp_score
        self._detected_by = detected_by
        self._log_timestamp = log_timestamp
        self._total_nodes_in_graph = total_nodes_in_graph
        self._source_file = source_file
        self._composite_score = composite_score
    
    # Getters
    @property
    def ip(self):
        return self._ip
    
    @property
    def recon_error(self):
        return self._recon_error
    
    @property
    def mlp_score(self):
        return self._mlp_score
    
    @property
    def detected_by(self):
        return self._detected_by
    
    @property
    def log_timestamp(self):
        return self._log_timestamp
    
    @property
    def total_nodes_in_graph(self):
        return self._total_nodes_in_graph
    
    @property
    def source_file(self):
        return self._source_file
    
    @property
    def composite_score(self):
        return self._composite_score
    
    # Setters
    @ip.setter
    def ip(self, value):
        self._ip = value
    
    @composite_score.setter
    def composite_score(self, value):
        self._composite_score = value
    
    def __str__(self):
        return (f"IP: {self.ip} | Score: {self.composite_score:.3f}\n"
                f"    Recon: {self.recon_error:.3f} | MLP: {self.mlp_score:.6f}\n"
                f"    Method: {self.detected_by} | Time: {self.log_timestamp}\n"
                f"    Nodes: {self.total_nodes_in_graph} | File: {self.source_file}")
