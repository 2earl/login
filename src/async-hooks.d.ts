// The part of node:async_hooks that src/shell.ts uses. Workers provide it with nodejs_compat;
// declaring it here keeps Node's whole type library out of the Worker's types.
declare module 'node:async_hooks' {
  export class AsyncLocalStorage<T> {
    run<R>(store: T, callback: () => R): R;
    getStore(): T | undefined;
  }
}
