@functools.cache
def _load_ccd_pickle_cached(
    path: os.PathLike[str],
) -> dict[str, Mapping[str, Sequence[str]]]:
  """Loads the CCD pickle file and caches it so that it is only loaded once."""
  with open(path, 'rb') as f:
    return pickle.loads(f.read())