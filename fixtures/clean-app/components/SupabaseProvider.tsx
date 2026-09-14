"use client";

import { createClient } from "@supabase/supabase-js";

// The anon key is meant to be public. It is safe precisely because row-level
// security is enabled on every table -- see supabase/migrations.
const SUPABASE_URL = "https://preflightfixture.supabase.co";
const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByZWZsaWdodGZpeHR1cmUiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTczNTY4OTYwMCwiZXhwIjoxODkzNDU2MDAwfQ.PREFLIGHTfixtureSIGNATUREnotVALIDanon";

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
