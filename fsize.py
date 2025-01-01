import subprocess
import os
import json
import requests
import re
import sys
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from typing import Dict, List
from dataclasses import dataclass

@dataclass
class PackageInfo:
    name: str
    size: int
    is_paid: bool = False
    version: str = ""
    description: str = ""
    latest_version: str = ""
    vulnerabilities: str = ""

@dataclass
class DockerSizeInfo:
    full: int
    slim: int
    alpine: int

class LocalRequirementsAnalyzer:
    def __init__(self):
        self.pypi_cache = {}
        self.npm_cache = {}
        self.known_paid_services = {
            'python': {'private-package', 'enterprise-pkg'},
            'node': {'private-module', 'enterprise-pkg'}
        }
        
        self.base_sizes = {
            'python': {
                'full': 100 * 1024 * 1024,    
                'slim': 40 * 1024 * 1024,     
                'alpine': 15 * 1024 * 1024,   
            },
            'node': {
                'full': 85 * 1024 * 1024,     
                'slim': 35 * 1024 * 1024,     
                'alpine': 12 * 1024 * 1024,   
            }
        }
        self.local_pypi_repo = {}  
        self.local_npm_repo = {}  

    def analyze_requirements(self, file_path: str, file_type: str) -> List[PackageInfo]:
        """Analyze requirements file (requirements.txt or package.json)"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if file_type == 'python':
            return self._analyze_python_requirements(file_path)
        elif file_type == 'node':
            return self._analyze_node_requirements(file_path)
        else:
            raise ValueError("Unsupported file type. Use 'python' or 'node'.")

    def _analyze_python_requirements(self, requirements_path: str) -> List[PackageInfo]:
        """Analyze Python requirements.txt file"""
        results = []
        with open(requirements_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    match = re.match(r'^([a-zA-Z0-9\-._]+)(?:[=<>!]+([a-zA-Z0-9\-._]+))?', line)
                    if match:
                        package_name, version = match.groups()
                        version = version or ""
                        
                        size = self._get_pypi_package_size(package_name)
                        is_paid = self._is_paid_package(package_name, 'python')
                        description = self._get_pypi_package_description(package_name)
                        latest_version = self._get_latest_pypi_version(package_name)
                        vulnerabilities = self._check_security_vulnerabilities(package_name, 'python')
                        
                        results.append(PackageInfo(
                            name=package_name,
                            size=size,
                            is_paid=is_paid,
                            version=version,
                            description=description,
                            latest_version=latest_version,
                            vulnerabilities=vulnerabilities
                        ))
        return results

    def _analyze_node_requirements(self, package_json_path: str) -> List[PackageInfo]:
        """Analyze Node.js package.json file"""
        results = []
        with open(package_json_path, 'r') as f:
            try:
                package_data = json.load(f)
                all_deps = {**package_data.get('dependencies', {}), **package_data.get('devDependencies', {})}
                
                for package_name, version in all_deps.items():
                    clean_version = re.sub(r'^[^0-9]*', '', version)
                    size = self._get_npm_package_size(package_name)
                    is_paid = self._is_paid_package(package_name, 'node')
                    description = self._get_npm_package_description(package_name)
                    latest_version = self._get_latest_npm_version(package_name)
                    vulnerabilities = self._check_security_vulnerabilities(package_name, 'node')
                    
                    results.append(PackageInfo(
                        name=package_name,
                        size=size,
                        is_paid=is_paid,
                        version=clean_version,
                        description=description,
                        latest_version=latest_version,
                        vulnerabilities=vulnerabilities
                    ))
            except json.JSONDecodeError:
                print(f"Error: Invalid package.json file")
                return []
        return results

    def _get_pypi_package_size(self, package_name: str) -> int:
        """Get package size from PyPI"""
        if package_name in self.pypi_cache:
            return self.pypi_cache[package_name]
        try:
            response = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if 'info' in data and 'version' in data['info']:
                    latest_version = data['info']['version']
                    if latest_version in data['releases']:
                        files = data['releases'][latest_version]
                        wheel_files = [f for f in files if f['packagetype'] == 'bdist_wheel']
                        if wheel_files:
                            size = wheel_files[0]['size']
                        else:
                            sdist_files = [f for f in files if f['packagetype'] == 'sdist']
                            size = sdist_files[0]['size'] if sdist_files else 0
                        self.pypi_cache[package_name] = size
                        return size
        except Exception as e:
            print(f"Error fetching PyPI package size for {package_name}: {e}")
        return 0

    def _get_npm_package_size(self, package_name: str) -> int:
        """Get package size from npm registry"""
        if package_name in self.npm_cache:
            return self.npm_cache[package_name]
        try:
            response = requests.get(f"https://registry.npmjs.org/{package_name}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                latest_version = data['dist-tags'].get('latest', '')
                if latest_version and latest_version in data['versions']:
                    version_data = data['versions'][latest_version]
                    size = version_data['dist'].get('unpackedSize', version_data['dist'].get('size', 0))
                    self.npm_cache[package_name] = size
                    return size
        except Exception as e:
            print(f"Error fetching npm package size for {package_name}: {e}")
        return 0

    def _is_paid_package(self, package_name: str, package_type: str) -> bool:
        """Check if package is a known paid package"""
        return package_name in self.known_paid_services[package_type]

    def _get_pypi_package_description(self, package_name: str) -> str:
        """Get package description from PyPI"""
        try:
            response = requests.get(f"https://pypi.org/pypi/{package_name}/json", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data['info'].get('description', 'No description available')
        except Exception as e:
            print(f"Error fetching PyPI package description for {package_name}: {e}")
        return "No description available"

    def _get_npm_package_description(self, package_name: str) -> str:
        """Get package description from NPM registry"""
        try:
            response = requests.get(f"https://registry.npmjs.org/{package_name}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return data.get('description', 'No description available')
        except Exception as e:
            print(f"Error fetching NPM package description for {package_name}: {e}")
        return "No description available"

    def _check_security_vulnerabilities(self, package_name: str, package_type: str) -> str:
        """Check for security vulnerabilities"""
        if package_type == 'python':
            return subprocess.run(['safety', 'check', '--bare', '--dependency', package_name], capture_output=True).stdout.decode().strip()
        elif package_type == 'node':
            return subprocess.run(['npm', 'audit', 'package', package_name], capture_output=True).stdout.decode().strip()
        else:
            return "No security audit available"

    def _get_latest_pypi_version(self, package_name: str) -> str:
        """Get the latest version for a Python package"""
        try:
            response = requests.get(f"https://pypi.org/pypi/{package_name}/json")
            if response.status_code == 200:
                data = response.json()
                return data['info']['version']
        except Exception as e:
            print(f"Error fetching PyPI package version for {package_name}: {e}")
        return ""

    def _get_latest_npm_version(self, package_name: str) -> str:
        """Get the latest version for an npm package"""
        try:
            response = requests.get(f"https://registry.npmjs.org/{package_name}")
            if response.status_code == 200:
                data = response.json()
                return data["dist-tags"]["latest"]
        except Exception as e:
            print(f"Error fetching npm package version for {package_name}: {e}")
        return ""

    def estimate_docker_sizes(self, packages: List[PackageInfo], package_type: str) -> DockerSizeInfo:
        """Estimate Docker image sizes for all variants"""
        packages_size = sum(pkg.size for pkg in packages)
        overhead = int(packages_size * 0.15)
        base_sizes = self.base_sizes[package_type]
        return DockerSizeInfo(
            full=base_sizes['full'] + packages_size + overhead,
            slim=base_sizes['slim'] + packages_size + overhead,
            alpine=base_sizes['alpine'] + packages_size + overhead
        )


    def _check_for_conflicts(self, package_list: List[PackageInfo]):
        """Detect version conflicts between dependencies"""
        version_map = {}
        conflicts = []
        for package in package_list:
            if package.name not in version_map:
                version_map[package.name] = package.version
            elif version_map[package.name] != package.version:
                conflicts.append((package.name, version_map[package.name], package.version))
        return conflicts

    def _get_local_package_info(self, package_name: str, package_type: str) -> Dict:
        """Retrieve package data from local package repository (mock-up example)"""
        if package_type == "python":
            return self.local_pypi_repo.get(package_name, {})
        elif package_type == "node":
            return self.local_npm_repo.get(package_name, {})
        return {}

    def analyze_multiple_projects(self, file_paths: List[str], file_type: str) -> List[PackageInfo]:
        """Analyze multiple requirements files (Python/Node.js)"""
        all_packages = []
        for path in file_paths:
            packages = self.analyze_requirements(path, file_type)
            all_packages.extend(packages)
        return all_packages

    def _get_release_notes(self, package_name: str, package_type: str) -> str:
        """Fetch release notes for a package"""
        if package_type == 'python':
            response = requests.get(f"https://pypi.org/pypi/{package_name}/json")
            return response.json().get("releases", {}).get("latest", {}).get("changelog", "No release notes available.")
        elif package_type == 'node':
            response = requests.get(f"https://registry.npmjs.org/{package_name}")
            return response.json().get("versions", {}).get("latest", {}).get("changelog", "No release notes available.")
        return ""

    def _get_package_cost_estimation(self, package_name: str, package_type: str) -> str:
        """Fetch cost estimation for enterprise packages (mock-up)"""
        if package_name in self.known_paid_services.get(package_type, []):
            return f"The enterprise package for {package_name} costs $XYZ/month"
        return "This package is free."

    def check_version_compatibility(self, package_name: str, required_version: str, package_type: str):
        """Check if the version is compatible with a specific Python/Node.js version"""
        return required_version in self._get_pypi_package_versions(package_name) if package_type == "python" else True

    def get_container_stats(self, container_id: str) -> Dict:
        """Fetch resource consumption metrics for a running container"""
        return subprocess.run(['docker', 'stats', '--no-stream', container_id], capture_output=True).stdout.decode()

    def _suggest_optimized_packages(self, package_name: str) -> str:
        """Suggest optimized packages based on user selection"""
        if package_name == "requests":
            return "Consider using 'http.client' for lower overhead."
        return "No optimization available."
def main(file_paths: List[str], file_type: str):
    try:
        analyzer = LocalRequirementsAnalyzer()
        packages = analyzer.analyze_multiple_projects(file_paths, file_type)
        
        output_file = "analysis_output.json"
        detailed_output = [{
            "name": package.name,
            "size": package.size,
            "is_paid": package.is_paid,
            "version": package.version,
            "description": package.description,
            "latest_version": package.latest_version,
            "vulnerabilities": package.vulnerabilities,
        } for package in packages]
        
        with open(output_file, 'w') as f:
            json.dump(detailed_output, f, indent=4)
        print(f"Analysis details saved to: {output_file}")
        
        # Display concise output to console
        concise_data = [{
            "Name": package.name,
            "Size (bytes)": package.size,
            "Is Paid": "Yes" if package.is_paid else "No"
        } for package in packages]
        
        df = pd.DataFrame(concise_data)
        print("\nDependency Overview:")
        print(df.to_string(index=False))
        
        docker_sizes = analyzer.estimate_docker_sizes(packages, file_type)
        print(f"\nDocker Sizes Estimate (full/slim/alpine): "
              f"{docker_sizes.full}/{docker_sizes.slim}/{docker_sizes.alpine} bytes")
        
        conflicts = analyzer._check_for_conflicts(packages)
        if conflicts:
            print("\nConflicts Detected:")
            for conflict in conflicts:
                print(f"{conflict[0]}: Version conflict between {conflict[1]} and {conflict[2]}")
        else:
            print("\nNo version conflicts detected.")
    
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except ValueError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script.py <file_paths> <file_type>")
        sys.exit(1)
    
    files = sys.argv[1].split(",")  
    file_type = sys.argv[2]  

    main(files, file_type)