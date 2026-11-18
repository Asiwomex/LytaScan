import { deliverReport, emailAvailable, emailSettings } from "../../../lib/report-email";

export async function GET() {
  return Response.json({ available: emailAvailable(emailSettings()) }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(request: Request) {
  return deliverReport(request, emailSettings());
}
