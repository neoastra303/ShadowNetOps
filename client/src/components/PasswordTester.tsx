import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Key, Check, X } from "lucide-react";

interface PasswordStrength {
  score: number;
  label: string;
  color: string;
  crackTime: string;
}

export default function PasswordTester() {
  const [password, setPassword] = useState("");
  const [strength, setStrength] = useState<PasswordStrength | null>(null);
  const [checks, setChecks] = useState({
    length: false,
    uppercase: false,
    lowercase: false,
    numbers: false,
    special: false,
  });

  useEffect(() => {
    if (!password) {
      setStrength(null);
      setChecks({
        length: false,
        uppercase: false,
        lowercase: false,
        numbers: false,
        special: false,
      });
      return;
    }

    const newChecks = {
      length: password.length >= 12,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      numbers: /[0-9]/.test(password),
      special: /[!@#$%^&*(),.?":{}|<>]/.test(password),
    };
    setChecks(newChecks);

    const score = Object.values(newChecks).filter(Boolean).length;
    
    const strengths: { [key: number]: PasswordStrength } = {
      0: { score: 0, label: "Very Weak", color: "text-destructive", crackTime: "Instant" },
      1: { score: 20, label: "Weak", color: "text-destructive", crackTime: "Minutes" },
      2: { score: 40, label: "Fair", color: "text-chart-4", crackTime: "Hours" },
      3: { score: 60, label: "Good", color: "text-chart-2", crackTime: "Days" },
      4: { score: 80, label: "Strong", color: "text-chart-1", crackTime: "Months" },
      5: { score: 100, label: "Very Strong", color: "text-chart-3", crackTime: "Years" },
    };

    setStrength(strengths[score]);
  }, [password]);

  return (
    <Card className="glow-green" data-testid="card-password-tester">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Key className="h-5 w-5 text-chart-3" />
          Password Strength Tester
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Input
          type="password"
          placeholder="Enter password to test..."
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="font-mono"
          data-testid="input-password"
        />

        {strength && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Strength:</span>
              <Badge className={`${strength.color} border-0 bg-transparent`} data-testid="badge-strength">
                {strength.label}
              </Badge>
            </div>
            
            <Progress value={strength.score} className="h-2" data-testid="progress-strength" />

            <div className="text-sm text-muted-foreground">
              Estimated crack time: <span className={strength.color} data-testid="text-crack-time">{strength.crackTime}</span>
            </div>

            <div className="space-y-2 pt-2" data-testid="container-password-checks">
              <h4 className="text-xs uppercase tracking-wide text-muted-foreground">Requirements</h4>
              {[
                { key: "length", label: "At least 12 characters" },
                { key: "uppercase", label: "Uppercase letters" },
                { key: "lowercase", label: "Lowercase letters" },
                { key: "numbers", label: "Numbers" },
                { key: "special", label: "Special characters" },
              ].map(({ key, label }) => (
                <div key={key} className="flex items-center gap-2 text-sm" data-testid={`check-${key}`}>
                  {checks[key as keyof typeof checks] ? (
                    <Check className="h-4 w-4 text-chart-3" />
                  ) : (
                    <X className="h-4 w-4 text-muted-foreground" />
                  )}
                  <span className={checks[key as keyof typeof checks] ? "text-foreground" : "text-muted-foreground"}>
                    {label}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
