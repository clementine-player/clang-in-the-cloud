import argparse
import difflib
import os
import subprocess
import sys
import urllib2


def main():
  parser = argparse.ArgumentParser(
      description='Reformats C++ source files that have changed from a given '
                  'git ref.')
  parser.add_argument('--url', default='http://localhost:10000/format',
      help='a URL of a Clang-in-the-cloud service')
  parser.add_argument('--ref', default='origin/master',
      help='the git-ref to compare against')
  parser.add_argument('-i', dest='inplace', action='store_true',
      help='edit files inplace instead of showing a diff')
  args = parser.parse_args()

  root_dir = subprocess.check_output([
      "git", "rev-parse", "--show-toplevel"]).strip()
  changed_files = subprocess.check_output([
      "git", "diff-index", args.ref, "--name-only"]).splitlines()

  if not changed_files:
    print >> sys.stderr, "No changes from %s" % args.ref
    return

  for filename in changed_files:
    path = os.path.join(root_dir, filename)
    original = open(path).read()
    response = urllib2.urlopen(args.url, original)
    formatted = response.read()

    if original == formatted:
      print >> sys.stderr, "%s: no changes" % filename
      continue

    diff = difflib.unified_diff(
        original.split('\n'), formatted.split('\n'),
        os.path.join("a", filename), os.path.join("b", filename),
        lineterm='')

    if args.inplace:
      with open(path, 'w') as fh:
        fh.write(formatted)

      print >> sys.stderr, '%s: %d insertion(s), %d deletion(s)' % (
          filename,
          sum(1 for x in diff if x.startswith('+')),
          sum(1 for x in diff if x.startswith('-')))
    else:
      print '\n'.join(diff)


if __name__ == "__main__":
  main()
