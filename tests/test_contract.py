"""Contract sweep: every registered module must construct and declare cleanly.

Catches the whole class of bug where OPTIONS is not a tuple (a single
``Option`` without a trailing comma), a duplicate NAME shadows another module,
or a module cannot be instantiated at all.
"""

from omni.core.module import FAMILIES, registry


def _all_modules():
    registry.load()
    for fam in FAMILIES:
        for cls in registry.all(fam):
            yield cls


def test_every_module_constructs_with_a_tuple_of_options():
    for cls in _all_modules():
        assert isinstance(cls.OPTIONS, tuple), f"{cls.NAME}: OPTIONS not a tuple"
        inst = cls()
        assert isinstance(inst.opts, dict)
        assert len(inst.opts) == len(cls.OPTIONS)
        for name, opt in inst.opts.items():
            assert opt.name == name
            assert callable(opt.resolve)


def test_every_module_has_metadata():
    for cls in _all_modules():
        assert cls.NAME and cls.DESCRIPTION and cls.FAMILY


def test_module_names_are_unique_per_family():
    for fam in FAMILIES:
        names = [m.NAME for m in registry.all(fam)]
        assert len(names) == len(set(names)), f"duplicate NAME in {fam}"


def test_module_names_are_prefixed_by_their_family():
    for cls in _all_modules():
        assert cls.NAME.startswith(cls.FAMILY + "."), cls.NAME


def test_required_options_have_descriptions():
    for cls in _all_modules():
        for opt in cls.OPTIONS:
            assert opt.description, f"{cls.NAME}.{opt.name} has no description"
