import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { AuthProvider } from "@omni-auth/react";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "OmniAuth Demo",
  description: "OmniAuth — Multi-Tenant Auth Demo",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable}`}>
      <body>
        <AuthProvider
          baseUrl={process.env.NEXT_PUBLIC_OMNI_AUTH_URL || "http://localhost:8080"}
          projectId={process.env.NEXT_PUBLIC_OMNI_PROJECT_ID || "00000000-0000-0000-0000-000000000000"}
        >
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
