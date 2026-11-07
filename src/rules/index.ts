import type { Rule } from '../types';
import { envRule } from './env';
import { firebaseRulesRule } from './firebase-rules';
import { secretsRule } from './secrets';
import { supabaseRlsRule } from './supabase-rls';

/** Every active rule. One file per rule in this folder. */
export const rules: readonly Rule[] = [secretsRule, envRule, supabaseRlsRule, firebaseRulesRule];
