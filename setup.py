"""Package verified frontend and evaluation resources into the Python release."""
from pathlib import Path
import shutil
from setuptools import setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).parent

class ProductBuild(build_py):
    def run(self):
        assets = ROOT / 'ui' / 'dist'
        if not (assets / 'index.html').is_file():
            raise RuntimeError('Build the product assets first: cd ui && npm ci && npm run build')
        super().run()
        package = Path(self.build_lib) / 'mirage_mcp'
        target = package / 'web'
        if target.exists(): shutil.rmtree(target)
        shutil.copytree(assets, target)
        evaluation = package / 'evaluation'
        evaluation.mkdir(parents=True, exist_ok=True)
        for source in (ROOT / 'benchmarks').glob('*.py'):
            content = source.read_text().replace('from benchmarks.', 'from mirage_mcp.evaluation.')
            (evaluation / source.name).write_text(content)

setup(cmdclass={'build_py': ProductBuild})
