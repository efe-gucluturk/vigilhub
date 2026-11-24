import type { Metadata, Viewport } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "VigilHub SOC Command Center",
  description: "Cross-tool security correlation for VigilSIEM, GitVigil and ReconVigil.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: "#070a10",
  colorScheme: "dark",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen">{children}</body>
    </html>
  );
}
