declare module 'picomatch' {
  export interface PicomatchOptions {
    dot?: boolean;
    nocase?: boolean;
    posix?: boolean;
    strictSlashes?: boolean;
    [key: string]: unknown;
  }

  export type Matcher = (test: string) => boolean;

  function picomatch(
    glob: string | readonly string[],
    options?: PicomatchOptions,
  ): Matcher;

  namespace picomatch {
    function isMatch(
      str: string,
      patterns: string | readonly string[],
      options?: PicomatchOptions,
    ): boolean;
  }

  export default picomatch;
}
