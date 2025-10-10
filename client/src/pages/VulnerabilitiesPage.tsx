import VulnerabilityAssessment from "@/components/VulnerabilityAssessment";

export default function VulnerabilitiesPage() {
  return (
    <div className="p-6" data-testid="page-vulnerabilities">
      <div className="mb-6">
        <h1 className="text-3xl font-bold gradient-cyan-magenta mb-2">Vulnerability Assessment</h1>
        <p className="text-muted-foreground">Identify and assess security vulnerabilities with CVE database</p>
      </div>
      
      <div className="max-w-4xl">
        <VulnerabilityAssessment />
      </div>
    </div>
  );
}
