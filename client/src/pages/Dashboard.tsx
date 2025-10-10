import { useState } from "react";
import MetricCard from "@/components/MetricCard";
import Terminal from "@/components/Terminal";
import { Activity, Shield, Zap, AlertTriangle } from "lucide-react";

interface TerminalLine {
  type: "input" | "output" | "error" | "success";
  content: string;
}

export default function Dashboard() {
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([
    { type: "output" as const, content: "RedTeam Terminal v2.1.0 - System Ready" },
    { type: "output" as const, content: "All security modules initialized" },
    { type: "success" as const, content: "✓ Network scanner online" },
    { type: "success" as const, content: "✓ Vulnerability database updated" },
    { type: "output" as const, content: "Type 'help' for available commands" },
  ]);

  const handleCommand = (cmd: string) => {
    const newLines = [...terminalLines, { type: "input" as const, content: cmd }];
    
    if (cmd.toLowerCase() === "help") {
      newLines.push(
        { type: "output", content: "Available commands:" },
        { type: "output", content: "  scan <target> - Scan network target" },
        { type: "output", content: "  vuln <target> - Run vulnerability assessment" },
        { type: "output", content: "  osint <query> - Perform OSINT lookup" },
        { type: "output", content: "  clear - Clear terminal" }
      );
    } else if (cmd.toLowerCase() === "clear") {
      setTerminalLines([]);
      return;
    } else if (cmd.toLowerCase().startsWith("scan")) {
      newLines.push(
        { type: "success", content: `✓ Initiating scan...` },
        { type: "output", content: "Navigate to Network Recon for detailed results" }
      );
    } else {
      newLines.push({ type: "error", content: `Command not recognized: ${cmd}` });
    }
    
    setTerminalLines(newLines);
  };

  return (
    <div className="space-y-6 p-6" data-testid="page-dashboard">
      <div>
        <h1 className="text-3xl font-bold gradient-cyan-magenta mb-2">Security Dashboard</h1>
        <p className="text-muted-foreground">Real-time threat intelligence and system status</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Active Scans"
          value="8"
          icon={Activity}
          trend={{ value: 12, isPositive: true }}
        />
        <MetricCard
          title="Vulnerabilities"
          value="23"
          icon={AlertTriangle}
          trend={{ value: 5, isPositive: false }}
        />
        <MetricCard
          title="Tools Running"
          value="5"
          icon={Zap}
        />
        <MetricCard
          title="Threats Blocked"
          value="142"
          icon={Shield}
          trend={{ value: 8, isPositive: true }}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <Terminal 
            lines={terminalLines} 
            onCommand={handleCommand}
            className="h-96"
          />
        </div>
        <div className="space-y-4">
          <div className="p-4 rounded-md border border-primary/30 bg-card/50" data-testid="card-recent-activity">
            <h3 className="text-sm font-semibold mb-3 text-primary">Recent Activity</h3>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Port scan completed</span>
                <span className="text-xs text-muted-foreground">2m ago</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">CVE database updated</span>
                <span className="text-xs text-muted-foreground">15m ago</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">OSINT query finished</span>
                <span className="text-xs text-muted-foreground">1h ago</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
