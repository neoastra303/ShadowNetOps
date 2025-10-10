import PasswordTester from "@/components/PasswordTester";

export default function PasswordPage() {
  return (
    <div className="p-6" data-testid="page-password">
      <div className="mb-6">
        <h1 className="text-3xl font-bold gradient-green-cyan mb-2">Password Strength Testing</h1>
        <p className="text-muted-foreground">Analyze password strength and estimate crack time</p>
      </div>
      
      <div className="max-w-2xl">
        <PasswordTester />
      </div>
    </div>
  );
}
