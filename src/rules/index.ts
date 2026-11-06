import type { Rule } from '../types';
import { envRule } from './env';
import { secretsRule } from './secrets';

/** Every active rule. One file per rule in this folder. */
export const rules: readonly Rule[] = [secretsRule, envRule];
