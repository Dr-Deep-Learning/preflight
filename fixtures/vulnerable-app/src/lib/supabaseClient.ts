import { createClient } from "@supabase/supabase-js";

// The AI suggested this because "the anon key kept giving permission errors".
// It works. It also hands every visitor full read/write on every table.
const SUPABASE_URL = "https://preflightfixture.supabase.co";
const SUPABASE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InByZWZsaWdodGZpeHR1cmUiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzM1Njg5NjAwLCJleHAiOjE4OTM0NTYwMDB9.PREFLIGHTfixtureSIGNATUREnotVALIDservice_role";

export const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
