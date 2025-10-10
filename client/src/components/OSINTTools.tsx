import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Search, Globe, User, Mail } from "lucide-react";

interface OSINTResult {
  type: string;
  data: string;
  found: boolean;
}

export default function OSINTTools() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<OSINTResult[]>([]);
  const [searching, setSearching] = useState(false);

  const handleSearch = () => {
    if (!query) return;
    setSearching(true);

    setTimeout(() => {
      const mockResults: OSINTResult[] = [
        { type: "Domain", data: "example.com registered since 2010", found: true },
        { type: "IP", data: "192.168.1.1 (Location: USA)", found: true },
        { type: "Email", data: "admin@example.com found in 3 breaches", found: true },
        { type: "Social", data: "Twitter: @example (2.5k followers)", found: true },
        { type: "WHOIS", data: "Registrar: GoDaddy LLC", found: true },
      ];
      setResults(mockResults);
      setSearching(false);
    }, 1500);
  };

  return (
    <Card data-testid="card-osint">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Globe className="h-5 w-5 text-primary" />
          OSINT Tools
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <Tabs defaultValue="domain" data-testid="tabs-osint">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="domain" data-testid="tab-domain">
              <Globe className="h-4 w-4 mr-2" />
              Domain
            </TabsTrigger>
            <TabsTrigger value="person" data-testid="tab-person">
              <User className="h-4 w-4 mr-2" />
              Person
            </TabsTrigger>
            <TabsTrigger value="email" data-testid="tab-email">
              <Mail className="h-4 w-4 mr-2" />
              Email
            </TabsTrigger>
          </TabsList>

          <TabsContent value="domain" className="space-y-3">
            <div className="flex gap-2">
              <Input
                placeholder="Enter domain (e.g., example.com)"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                className="font-mono text-sm"
                data-testid="input-osint-query"
              />
              <Button 
                onClick={handleSearch}
                disabled={searching || !query}
                data-testid="button-search"
              >
                <Search className="h-4 w-4 mr-2" />
                {searching ? "Searching..." : "Search"}
              </Button>
            </div>
          </TabsContent>

          <TabsContent value="person" className="space-y-3">
            <div className="flex gap-2">
              <Input
                placeholder="Enter name or username"
                className="font-mono text-sm"
                data-testid="input-person"
              />
              <Button data-testid="button-search-person">
                <Search className="h-4 w-4 mr-2" />
                Search
              </Button>
            </div>
          </TabsContent>

          <TabsContent value="email" className="space-y-3">
            <div className="flex gap-2">
              <Input
                placeholder="Enter email address"
                className="font-mono text-sm"
                data-testid="input-email"
              />
              <Button data-testid="button-search-email">
                <Search className="h-4 w-4 mr-2" />
                Search
              </Button>
            </div>
          </TabsContent>
        </Tabs>

        {results.length > 0 && (
          <div className="space-y-2 pt-2" data-testid="container-osint-results">
            <h4 className="text-xs uppercase tracking-wide text-muted-foreground">Results</h4>
            <div className="space-y-1">
              {results.map((result, i) => (
                <div 
                  key={i}
                  className="p-2 rounded-md bg-accent/30 hover-elevate flex items-start justify-between"
                  data-testid={`row-result-${i}`}
                >
                  <div>
                    <div className="text-xs text-primary font-mono">{result.type}</div>
                    <div className="text-sm">{result.data}</div>
                  </div>
                  {result.found && (
                    <div className="h-2 w-2 rounded-full bg-chart-3" data-testid={`indicator-found-${i}`} />
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
