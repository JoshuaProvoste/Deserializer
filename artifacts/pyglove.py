  def decode(self, json_value: JSONValueType) -> Any:
    assert isinstance(json_value, str), json_value
    try:
      return pickle.loads(base64.decodebytes(json_value.encode('utf-8')))
    except Exception as e:
      raise ValueError('Cannot decode opaque object with pickle.') from e