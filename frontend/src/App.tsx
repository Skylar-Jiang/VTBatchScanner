import { useState } from "react";

import { AppShell } from "@/components/app-shell";
import { Toaster } from "@/components/ui/sonner";
import { BatchesPage } from "@/features/batches/batches-page";
import { DashboardPage } from "@/features/dashboard/dashboard-page";
import { NewAnalysisPage } from "@/features/new-analysis/new-analysis-page";
import { SampleDetailPage } from "@/features/samples/sample-detail-page";
import { SamplesPage } from "@/features/samples/samples-page";
import { type SampleRow, type View } from "@/lib/workspace";

export default function App() {
  const [view, setView] = useState<View>("dashboard");
  const [selectedSample, setSelectedSample] = useState<SampleRow | null>(null);
  function goToSample(sample: SampleRow) { setSelectedSample(sample); setView("detail"); }
  return <><AppShell activeView={view} onViewChange={setView}>{view === "dashboard" && <DashboardPage onViewChange={setView} />}{view === "samples" && <SamplesPage onSelect={goToSample} />}{view === "new" && <NewAnalysisPage onViewChange={setView} />}{view === "batches" && <BatchesPage />}{view === "detail" && selectedSample && <SampleDetailPage onBack={() => setView("samples")} sample={selectedSample} />}</AppShell><Toaster position="top-right" richColors /></>;
}
