import { useState, useEffect, useRef } from "react";
import { Card } from "@/components/ui/card";

interface TerminalLine {
  type: "input" | "output" | "error" | "success";
  content: string;
}

interface TerminalProps {
  lines: TerminalLine[];
  onCommand?: (command: string) => void;
  prompt?: string;
  className?: string;
}

export default function Terminal({ lines, onCommand, prompt = "redteam@cyber:~$", className = "" }: TerminalProps) {
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [lines]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;
    
    setHistory([...history, input]);
    setHistoryIndex(-1);
    onCommand?.(input);
    setInput("");
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (history.length > 0) {
        const newIndex = historyIndex === -1 ? history.length - 1 : Math.max(0, historyIndex - 1);
        setHistoryIndex(newIndex);
        setInput(history[newIndex]);
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIndex !== -1) {
        const newIndex = Math.min(history.length - 1, historyIndex + 1);
        setHistoryIndex(newIndex);
        setInput(history[newIndex]);
      }
    }
  };

  return (
    <Card className={`bg-background border-primary/30 shadow-lg shadow-primary/10 overflow-hidden ${className}`} data-testid="terminal-container">
      <div className="scanlines h-full">
        <div className="p-4 space-y-1 font-mono text-sm h-full flex flex-col">
          <div className="flex-1 overflow-y-auto space-y-1 min-h-0" data-testid="terminal-output">
            {lines.map((line, i) => (
              <div key={i} className="leading-relaxed" data-testid={`terminal-line-${i}`}>
                {line.type === "input" && (
                  <div className="flex gap-2">
                    <span className="text-primary" data-testid="terminal-prompt">{prompt}</span>
                    <span className="text-foreground">{line.content}</span>
                  </div>
                )}
                {line.type === "output" && (
                  <div className="text-muted-foreground pl-2">{line.content}</div>
                )}
                {line.type === "error" && (
                  <div className="text-destructive pl-2">{line.content}</div>
                )}
                {line.type === "success" && (
                  <div className="text-chart-3 pl-2">{line.content}</div>
                )}
              </div>
            ))}
            <div ref={bottomRef} />
          </div>
          
          <form onSubmit={handleSubmit} className="flex gap-2 pt-2 border-t border-primary/20">
            <span className="text-primary" data-testid="terminal-prompt-active">{prompt}</span>
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              className="flex-1 bg-transparent outline-none text-foreground font-mono"
              autoFocus
              data-testid="input-terminal"
            />
            <span className="text-primary cursor-blink">▊</span>
          </form>
        </div>
      </div>
    </Card>
  );
}
