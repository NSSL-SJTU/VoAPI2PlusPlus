METHOD_QUERY = """
(annotation
  arguments: (annotation_argument_list
    (element_value_pair
      key: (identifier) @_k
      value: (_) @method_value
      (#eq? @_k "method"))))
"""