import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = "https://gvwllchauxbiwpdxxxqr.supabase.co";
const SUPABASE_KEY = "sb_publishable_8XWi5Sb0F-JVPjS1Rdx4Dg_Lv4jJRmg";

export const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);