__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


from parameterized import param, parameterized, parameterized_class


def get_func_name(func, param_num, params):
    suffix = params.kwargs.get("name")
    if not suffix:
        if params.args:
            suffix = params.args[0]
        else:
            raise AttributeError(
                "Please use string or integer type as first function parameter "
                "or add the 'name' argument."
            )

    return f"{func.__name__}_{parameterized.to_safe_name(f'{suffix}')}"


def get_class_name(cls, num, params_dict: dict):
    if params_dict.get("name"):
        suffix = parameterized.to_safe_name(params_dict["name"])
    else:
        raise AttributeError("Please add the 'name' variable to the class parameters.")

    return f"{cls.__name__}{parameterized.to_safe_name(suffix)}"


def parameterize_class(
    attrs, input_values=None, class_name_func=get_class_name, classname_func=None
):
    """Default wrapper for parametrizing a class from `parameterized` library."""
    return parameterized_class(attrs, input_values, class_name_func, classname_func)


class parameterize(parameterized):
    @classmethod
    def expand(
        cls,
        input_,
        name_func=get_func_name,
        doc_func=None,
        skip_on_empty=False,
        namespace=None,
        **legacy,
    ):
        """Default wrapper for parametrizing a function from `parameterized` library."""
        return super().expand(input_, name_func, doc_func, skip_on_empty, namespace, **legacy)
