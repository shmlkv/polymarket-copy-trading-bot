import { NextResponse } from 'next/server';
import { spawn } from 'child_process';
import * as path from 'path';
import { ActionRequest, ActionResponse, ActionType } from '@/types/settings';

const PROJECT_ROOT = path.join(process.cwd(), '..');

// Map actions to npm scripts
const actionScripts: Record<ActionType, string> = {
  'health-check': 'health-check',
  'check-stats': 'check-stats',
  'manual-sell': 'manual-sell',
  'close-resolved': 'close-resolved',
  'redeem-resolved': 'redeem-resolved',
  'close-stale': 'close-stale',
};

// Execute npm script and return output
async function runScript(script: string, args: string[] = []): Promise<{ success: boolean; output: string }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    const errorChunks: Buffer[] = [];

    const proc = spawn('npm', ['run', script, '--', ...args], {
      cwd: PROJECT_ROOT,
      env: { ...process.env, FORCE_COLOR: '0' }, // Disable colors for clean output
      shell: true,
    });

    proc.stdout.on('data', (data) => chunks.push(data));
    proc.stderr.on('data', (data) => errorChunks.push(data));

    const timeout = setTimeout(() => {
      proc.kill();
      resolve({
        success: false,
        output: 'Script timed out after 60 seconds',
      });
    }, 60000); // 60 second timeout

    proc.on('close', (code) => {
      clearTimeout(timeout);
      const stdout = Buffer.concat(chunks).toString('utf-8');
      const stderr = Buffer.concat(errorChunks).toString('utf-8');

      // Clean ANSI escape codes
      const cleanOutput = (stdout + (stderr ? `\n${stderr}` : ''))
        .replace(/\x1b\[[0-9;]*m/g, '') // Remove ANSI color codes
        .replace(/\x1b\[[0-9;]*[A-Za-z]/g, '') // Remove other ANSI sequences
        .trim();

      resolve({
        success: code === 0,
        output: cleanOutput || (code === 0 ? 'Script completed successfully' : 'Script failed'),
      });
    });

    proc.on('error', (error) => {
      clearTimeout(timeout);
      resolve({
        success: false,
        output: `Failed to start script: ${error.message}`,
      });
    });
  });
}

export async function POST(request: Request) {
  try {
    const body: ActionRequest = await request.json();
    const { action, params } = body;

    if (!action || !actionScripts[action]) {
      return NextResponse.json(
        { error: `Invalid action: ${action}` },
        { status: 400 }
      );
    }

    const script = actionScripts[action];
    const args: string[] = [];

    // Add parameters for specific actions
    if (action === 'manual-sell' && params?.keyword) {
      args.push(params.keyword);
    }

    console.log(`Running action: ${action} (npm run ${script})`);

    const result = await runScript(script, args);

    const response: ActionResponse = {
      success: result.success,
      action,
      output: result.output,
      error: result.success ? undefined : result.output,
    };

    return NextResponse.json(response);
  } catch (error) {
    console.error('Error executing action:', error);
    return NextResponse.json(
      {
        success: false,
        action: 'unknown',
        output: '',
        error: `Failed to execute action: ${error instanceof Error ? error.message : 'Unknown error'}`,
      },
      { status: 500 }
    );
  }
}
