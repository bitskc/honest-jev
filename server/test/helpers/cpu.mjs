// CPU time (user + system) of this process, in milliseconds.
//
// The guard's speed tests exist to catch a super-linear scan: the bugs they pin cost seconds where the fixed code needs
// milliseconds. Wall-clock time cannot tell that apart from a loaded host (a run at load average 17 on 16 cores took 897 ms
// against a 500 ms bound for work that needs a few ms). The guard is synchronous CPU work with no I/O, so the CPU time the
// process spends on it is the same however many other processes compete for the cores. Bounds stay in milliseconds and stay
// generous; they fail on an algorithmic blowup, not on a busy machine.
export const cpuNow = () => {
  const u = process.cpuUsage();
  return (u.user + u.system) / 1000;
};
