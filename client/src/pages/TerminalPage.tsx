import { useState } from "react";
import Terminal from "@/components/Terminal";

interface TerminalLine {
  type: "input" | "output" | "error" | "success";
  content: string;
}

export default function TerminalPage() {
  const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([
    { type: "output" as const, content: "RedTeam Terminal v2.1.0 - Interactive Mode" },
    { type: "output" as const, content: "==========================================" },
    { type: "output" as const, content: "" },
    { type: "output" as const, content: "Available Commands:" },
    { type: "output" as const, content: "  help     - Show this help message" },
    { type: "output" as const, content: "  scan     - Scan network targets" },
    { type: "output" as const, content: "  vuln     - Vulnerability assessment" },
    { type: "output" as const, content: "  osint    - OSINT operations" },
    { type: "output" as const, content: "  pwd-test - Test password strength" },
    { type: "output" as const, content: "  clear    - Clear terminal" },
    { type: "output" as const, content: "" },
  ]);

  const handleCommand = (cmd: string) => {
    const newLines = [...terminalLines, { type: "input" as const, content: cmd }];
    const command = cmd.toLowerCase().trim();
    
    if (command === "help") {
      newLines.push(
        { type: "output", content: "" },
        { type: "output", content: "RedTeam Terminal Commands:" },
        { type: "output", content: "  scan <ip/domain>  - Network reconnaissance" },
        { type: "output", content: "  vuln <target>     - Vulnerability scan" },
        { type: "output", content: "  osint <query>     - OSINT lookup" },
        { type: "output", content: "  pwd-test          - Password strength test" },
        { type: "output", content: "  clear             - Clear screen" },
        { type: "output", content: "" }
      );
    } else if (command === "clear") {
      setTerminalLines([]);
      return;
    } else if (command.startsWith("scan")) {
      const target = command.split(" ")[1] || "localhost";
      newLines.push(
        { type: "success", content: `✓ Initiating scan on ${target}...` },
        { type: "output", content: "Discovering open ports..." },
        { type: "success", content: "Port 22: OPEN - SSH" },
        { type: "success", content: "Port 80: OPEN - HTTP" },
        { type: "success", content: "Port 443: OPEN - HTTPS" },
        { type: "output", content: `Scan complete. Found 3 open ports.` },
        { type: "output", content: "" }
      );
    } else if (command.startsWith("vuln")) {
      const target = command.split(" ")[1] || "target";
      newLines.push(
        { type: "success", content: `✓ Running vulnerability assessment on ${target}...` },
        { type: "output", content: "Checking CVE database..." },
        { type: "error", content: "! CRITICAL: SQL Injection vulnerability detected" },
        { type: "error", content: "! HIGH: Weak SSL/TLS configuration" },
        { type: "output", content: "Assessment complete. 2 vulnerabilities found." },
        { type: "output", content: "" }
      );
    } else if (command.startsWith("osint")) {
      const query = command.split(" ")[1] || "query";
      newLines.push(
        { type: "success", content: `✓ Performing OSINT on ${query}...` },
        { type: "output", content: "Querying public databases..." },
        { type: "success", content: "Domain registration: 2015" },
        { type: "success", content: "Email found in 3 breaches" },
        { type: "success", content: "Social media profiles: 5 found" },
        { type: "output", content: "" }
      );
    } else if (command === "pwd-test") {
      newLines.push(
        { type: "output", content: "Navigate to Password Test page for interactive testing" },
        { type: "output", content: "" }
      );
    } else if (command) {
      newLines.push(
        { type: "error", content: `Command not found: ${command}` },
        { type: "output", content: "Type 'help' for available commands" },
        { type: "output", content: "" }
      );
    }
    
    setTerminalLines(newLines);
  };

  return (
    <div className="p-6 h-full" data-testid="page-terminal">
      <div className="mb-4">
        <h1 className="text-3xl font-bold gradient-green-cyan mb-2">Interactive Terminal</h1>
        <p className="text-muted-foreground">Execute security operations via command line</p>
      </div>
      
      <Terminal 
        lines={terminalLines} 
        onCommand={handleCommand}
        className="h-[calc(100vh-200px)]"
      />
    </div>
  );
}
