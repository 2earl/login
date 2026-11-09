import { accountEventsBinding } from './deletion-notices';
import { SERVICES } from './services';

/**
 * Each 2earl service's part of "Download your data" (DATA_PROTECTION §6), asked of its
 * `AccountEvents.exportUser` over the binding in src/services.ts. One place for the user to get
 * everything 2earl holds about them. A service that can't answer is named in the file rather than
 * failing the whole download.
 */

const EXPORT_TIMEOUT_MS = 10_000;

export type ServiceExport =
  | { service: string; status: 'included'; data: unknown }
  | { service: string; status: 'unavailable' | 'not connected'; note: string };

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error('timeout'));
    }, ms);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer !== null) clearTimeout(timer);
  });
}

export async function exportFromServices(
  env: Env,
  userId: string,
): Promise<Record<string, ServiceExport>> {
  const entries = await Promise.all(
    SERVICES.map(async (service): Promise<[string, ServiceExport]> => {
      const binding = accountEventsBinding(env, service.deletionBinding);
      if (!binding) {
        return [
          service.id,
          {
            service: service.name,
            status: 'not connected',
            note: 'This service holds no data yet.',
          },
        ];
      }
      try {
        const data = await withTimeout(binding.exportUser(userId), EXPORT_TIMEOUT_MS);
        return [service.id, { service: service.name, status: 'included', data }];
      } catch (error) {
        console.error(
          'service export failed',
          service.id,
          error instanceof Error ? error.name : 'unknown',
        );
        return [
          service.id,
          {
            service: service.name,
            status: 'unavailable',
            note: 'This service could not answer just now. Download again later to include it.',
          },
        ];
      }
    }),
  );
  return Object.fromEntries(entries);
}
