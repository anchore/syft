
def dig(target, *keys, **kwargs):
    """
    Traverse a nested set of dictionaries, tuples, or lists similar to ruby's dig function.
    """
    end_of_chain = target
    for key in keys:
        if isinstance(end_of_chain, dict) and key in end_of_chain:
            end_of_chain = end_of_chain[key]
        elif isinstance(end_of_chain, (list, tuple)) and isinstance(key, int):
            end_of_chain = end_of_chain[key]
        else:
            if 'fail' in kwargs and kwargs['fail'] is True:
                if isinstance(end_of_chain, dict):
                    raise KeyError
                else:
                    raise IndexError
            else:
                return None

    return end_of_chain
