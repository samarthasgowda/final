import subprocess
import shlex

class VolatilityRunner:
    def __init__(self, vol_cmd="volatility3"):
        # Store the base command (string)
        self.vol_cmd = vol_cmd

    def _run(self, args, outdir):
        """
        Run a volatility command with args.
        Splits vol_cmd safely so '--volcmd "python /path/to/vol.py"' works.
        """
        # shlex.split will turn "python /path/to/vol.py" into ["python", "/path/to/vol.py"]
        cmd = shlex.split(self.vol_cmd) + args
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Write output & errors to files for debugging
        with open(f"{outdir}/vol_output.txt", "a") as f:
            f.write(proc.stdout)
        with open(f"{outdir}/vol_errors.txt", "a") as f:
            f.write(proc.stderr)

        return proc.stdout
