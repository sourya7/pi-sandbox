export class RuntimeLifecycleGate {
  private mutationTail: Promise<void> = Promise.resolve();
  private activeChildren = 0;
  private pendingMutations = 0;
  private childrenBlocked = false;
  private readonly admissionWaiters = new Set<() => void>();
  private readonly exitWaiters = new Set<() => void>();

  async runChild<T>(operation: () => Promise<T>): Promise<T> {
    while (this.childrenBlocked) {
      await new Promise<void>((resolve) => this.admissionWaiters.add(resolve));
    }
    this.activeChildren++;
    try {
      return await operation();
    } finally {
      this.activeChildren--;
      if (this.activeChildren === 0) {
        for (const resolve of this.exitWaiters) resolve();
        this.exitWaiters.clear();
      }
    }
  }

  mutate<T>(operation: () => Promise<T>): Promise<T> {
    this.pendingMutations++;
    this.childrenBlocked = true;
    const runExclusive = async () => {
      if (this.activeChildren > 0) {
        await new Promise<void>((resolve) => this.exitWaiters.add(resolve));
      }
      try {
        return await operation();
      } finally {
        this.pendingMutations--;
        if (this.pendingMutations === 0) {
          this.childrenBlocked = false;
          for (const resolve of this.admissionWaiters) resolve();
          this.admissionWaiters.clear();
        }
      }
    };
    const run = this.mutationTail.then(runExclusive, runExclusive);
    this.mutationTail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}
