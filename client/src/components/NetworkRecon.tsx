import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Search, Wifi, WifiOff } from "lucide-react";

interface Port {
  port: number;
  status: "open" | "closed" | "filtered";
  service: string;
}

export default function NetworkRecon() {
  const [target, setTarget] = useState("");
  const [scanning, setScanning] = useState(false);
  const [ports, setPorts] = useState<Port[]>([]);

  const handleScan = () => {
    if (!target) return;
    setScanning(true);
    
    // Mock scan simulation
    setTimeout(() => {
      const mockPorts: Port[] = [
        { port: 22, status: "open", service: "SSH" },
        { port: 80, status: "open", service: "HTTP" },
        { port: 443, status: "open", service: "HTTPS" },
        { port: 3306, status: "closed", service: "MySQL" },
        { port: 8080, status: "filtered", service: "HTTP-Proxy" },
        { port: 21, status: "open", service: "FTP" },
      ];
      setPorts(mockPorts);
      setScanning(false);
    }, 2000);
  };

  return (
    <Card className="glow-cyan" data-testid="card-network-recon">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Search className="h-5 w-5 text-primary" />
          Network Reconnaissance
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Input
            placeholder="Enter IP or domain (e.g., 192.168.1.1)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="font-mono text-sm"
            data-testid="input-target"
          />
          <Button 
            onClick={handleScan} 
            disabled={scanning || !target}
            className="min-w-24"
            data-testid="button-scan"
          >
            {scanning ? "Scanning..." : "Scan"}
          </Button>
        </div>

        {ports.length > 0 && (
          <div className="space-y-2" data-testid="container-scan-results">
            <h3 className="text-xs uppercase tracking-wide text-muted-foreground">Scan Results</h3>
            <div className="space-y-1">
              {ports.map((port) => (
                <div 
                  key={port.port} 
                  className="flex items-center justify-between p-2 rounded-md bg-accent/30 hover-elevate"
                  data-testid={`row-port-${port.port}`}
                >
                  <div className="flex items-center gap-3">
                    {port.status === "open" ? (
                      <Wifi className="h-4 w-4 text-chart-3" />
                    ) : (
                      <WifiOff className="h-4 w-4 text-muted-foreground" />
                    )}
                    <span className="font-mono text-sm" data-testid={`text-port-${port.port}`}>Port {port.port}</span>
                    <span className="text-sm text-muted-foreground">{port.service}</span>
                  </div>
                  <Badge 
                    variant={port.status === "open" ? "default" : "secondary"}
                    className={port.status === "open" ? "bg-chart-3/20 text-chart-3" : ""}
                    data-testid={`badge-status-${port.port}`}
                  >
                    {port.status}
                  </Badge>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
