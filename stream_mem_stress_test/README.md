# Streams - Memory Stress Test and Memory Profiling
This directory contains test code for running a memory profiler when using the `encryptStream` and `decryptUnsignedMessageStream`.
This directory contains everything you need to run a memory profiler on these two operations.

## Requirements
- Node >= 12
- Chrome Browser

## How to run the application and memory profiler
1. For easier debugging open two chrome windows
  1. One where you can look at the profiler
  2. One where you can navigate through the application paths.
1. On Chrome, navigate to: `chrome://inspect/#devices`
1. Make sure you are in the `stream_mem_stress_test` directory.
1. Start debugger and server by running `npm run start`
1. On the devices page click on `inspect` for the remote target that just appeared
  1. Navigate to the Memory tab. You will have three options:
    1. Heap snapshot
        - Useful to focus on a specific action during runtime.
    1. Allocation instrumentation on timeline
        - Works better for our stress tests since we can see memory allocation and
        garbage collection during runtime
    1. Allocation Sampling (not useful for our test)
1. Navigate to any of the provided paths and watch memory allocation and garbage collection in
  real time 🍿
