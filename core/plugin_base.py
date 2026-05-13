class PluginBase:

    name = "base"
    category = "generic"

    def run(self, target):
        raise NotImplementedError("Plugin must implement run()")
