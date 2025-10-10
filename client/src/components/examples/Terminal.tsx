import Terminal from "../Terminal";
import { useState } from "react";

export default function TerminalExample() {
  const [lines, setLines] = useState([
    { type: "output" as const, content: "RedTeam Terminal v2.1.0 - Initialized" },
    { type: "output" as const, content: "Type 'help' for available commands" },
    { type: "input" as const, content: "scan 192.168.1.1" },
    { type: "success" as const, content: "✓ Scan initiated on target 192.168.1.1" },
    { type: "output" as const, content: "Port 22: OPEN - SSH" },
    { type: "output" as const, content: "Port 80: OPEN - HTTP" },
    { type: "output" as const, content: "Port 443: OPEN - HTTPS" },
  ]);

  const handleCommand = (cmd: string) => {
    setLines([...lines, { type: "input", content: cmd }]);
    setTimeout(() => {
      setLines(prev => [...prev, { type: "success", content: `Executed: ${cmd}` }]);
    }, 100);
  };

  return (
    <div className="h-96">
      <Terminal lines={lines} onCommand={handleCommand} />
    </div>
  );
}
