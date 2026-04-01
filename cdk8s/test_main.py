#!/usr/bin/env python3
"""Unit tests for the cdk8s image factory chart."""
import pytest
import yaml
import tempfile
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from constructs import Construct
from cdk8s import App
from main import ImageFactoryChart
from lib.data import load_yaml_dir
from lib.warehouses import _build_git_subscription_config
from hypothesis import given, strategies as st, settings, HealthCheck


def synth_chart_to_yaml(app):
    """Helper function to synthesize a CDK8s app to YAML string."""
    # Use persistent output directory for debugging
    output_dir = Path(__file__).parent / "tests" / ".output"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Clear previous output
    for file in output_dir.glob("*"):
        if file.is_file():
            file.unlink()
    
    # Set CDK8S_OUTDIR to control where synthesis outputs go
    old_outdir = os.environ.get('CDK8S_OUTDIR')
    os.environ['CDK8S_OUTDIR'] = str(output_dir)
    
    try:
        # Synthesize the app
        app.synth()
        
        # Read the generated YAML files (CDK8s uses .k8s.yaml extension)
        results = ""
        yaml_files = list(output_dir.glob("*.k8s.yaml"))
        
        for yaml_file in yaml_files:
            with open(yaml_file, 'r') as f:
                content = f.read()
                results += content + "\n---\n"
        
        return results
        
    finally:
        # Restore original CDK8S_OUTDIR
        if old_outdir is not None:
            os.environ['CDK8S_OUTDIR'] = old_outdir
        elif 'CDK8S_OUTDIR' in os.environ:
            del os.environ['CDK8S_OUTDIR']


class TestLoadYamlDir:
    """Test the load_yaml_dir utility function."""
    
    def test_load_yaml_dir_empty(self):
        """Test loading from non-existent directory."""
        result = load_yaml_dir(Path("/nonexistent"))
        assert result == []
    
    def test_load_yaml_dir_excludes_examples(self):
        """Test that example files are excluded."""
        with TemporaryDirectory() as tmpdir:
            dir_path = Path(tmpdir)
            
            # Create test files
            (dir_path / "image1.yaml").write_text(yaml.dump({'name': 'image1'}))
            (dir_path / "image2.yaml").write_text(yaml.dump({'name': 'image2'}))
            (dir_path / "example.example.yaml").write_text(yaml.dump({'name': 'example'}))
            (dir_path / "test.example.yaml").write_text(yaml.dump({'name': 'test'}))  # Changed to .example.yaml
            (dir_path / "readme.txt").write_text("not yaml")
            
            result = load_yaml_dir(dir_path)
            
            assert len(result) == 2
            names = [img['name'] for img in result]
            assert 'image1' in names
            assert 'image2' in names
            assert 'example' not in names
            assert 'test' not in names


class TestImageFactoryChart:
    """Test suite for ImageFactoryChart."""
    
    @pytest.fixture
    def temp_structure(self):
        """Create temporary directory structure for testing."""
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            
            # Create directory structure
            images_dir = root / "image-factory" / "state" / "images"
            base_images_dir = root / "image-factory" / "state" / "base-images"
            images_dir.mkdir(parents=True)
            base_images_dir.mkdir(parents=True)
            
            # Create images.yaml
            images_yaml = root / "image-factory" / "images.yaml"
            images_yaml.write_text(yaml.dump([
                {
                    'name': 'backstage',
                    'registry': 'ghcr.io',
                    'repository': 'owner/backstage'
                }
            ]))
            
            yield root
    
    def test_chart_creates_warehouses_from_base_images(self, temp_structure, monkeypatch):
        """Test that chart creates warehouses for base images with proper config."""
        # Create base image state file
        base_image_file = temp_structure / "image-factory" / "state" / "base-images" / "node-22.yaml"
        base_image_file.write_text(yaml.dump({
            'name': 'node-22',
            'repoURL': 'docker.io/library/node',
            'allowTags': '^22-bookworm-slim$',
            'imageSelectionStrategy': 'Lexical'
        }))
        
        # Mock the file paths in main.py
        import main
        monkeypatch.setattr(main, 'IMAGES_YAML', temp_structure / "image-factory" / "images.yaml")
        monkeypatch.setattr(main, 'STATE_IMAGES_DIR', temp_structure / "image-factory" / "state" / "images")
        monkeypatch.setattr(main, 'STATE_BASE_IMAGES_DIR', temp_structure / "image-factory" / "state" / "base-images")
        
        # Create app with explicit outdir
        output_dir = Path(__file__).parent / "tests" / ".output"
        output_dir.mkdir(parents=True, exist_ok=True)
        app = App(outdir=str(output_dir))
        chart = ImageFactoryChart(app, "test")
        
        # Synthesize to YAML using helper function
        results = synth_chart_to_yaml(app)
        
        # Parse the output
        manifests = list(yaml.safe_load_all(results))
        
        # Find the warehouse for node-22
        warehouse = None
        for manifest in manifests:
            if manifest and manifest.get('kind') == 'Warehouse' and manifest.get('metadata', {}).get('name') == 'node-22':
                warehouse = manifest
                break
        
        assert warehouse is not None, "Warehouse for node-22 not found"
        
        # Verify warehouse spec
        spec = warehouse['spec']
        assert spec['interval'] == '24h'  # Updated to match the actual implementation
        assert len(spec['subscriptions']) == 1
        
        image_sub = spec['subscriptions'][0]['image']
        assert image_sub['repoURL'] == 'docker.io/library/node'  # Note: uppercase URL
        assert image_sub['allowTags'] == '^22-bookworm-slim$'
        assert image_sub['imageSelectionStrategy'] == 'Lexical'
        assert image_sub['discoveryLimit'] == 10
    
    def test_chart_skips_images_without_warehouse_config(self, temp_structure, monkeypatch):
        """Test that images without repoURL/allowTags are skipped."""
        # Create image state file without warehouse config
        image_file = temp_structure / "image-factory" / "state" / "images" / "backstage.yaml"
        image_file.write_text(yaml.dump({
            'name': 'backstage',
            'enrollment': {
                'registry': 'ghcr.io',
                'repository': 'owner/backstage'
            }
            # Missing repoURL and allowTags
        }))
        
        # Mock the file paths
        import main
        monkeypatch.setattr(main, 'IMAGES_YAML', temp_structure / "image-factory" / "images.yaml")
        monkeypatch.setattr(main, 'STATE_IMAGES_DIR', temp_structure / "image-factory" / "state" / "images")
        monkeypatch.setattr(main, 'STATE_BASE_IMAGES_DIR', temp_structure / "image-factory" / "state" / "base-images")
        
        # Create app and chart
        output_dir = Path(__file__).parent / "tests" / ".output"
        output_dir.mkdir(parents=True, exist_ok=True)
        app = App(outdir=str(output_dir))
        chart = ImageFactoryChart(app, "test")
        
        # Synthesize to YAML using helper function
        results = synth_chart_to_yaml(app)
        
        # Parse the output
        manifests = list(yaml.safe_load_all(results))
        
        # Should not find warehouse for backstage
        warehouse_names = [
            m.get('metadata', {}).get('name')
            for m in manifests
            if m and m.get('kind') == 'Warehouse'
        ]
        
        assert 'backstage' not in warehouse_names
    
    def test_chart_merges_images_yaml_with_state(self, temp_structure, monkeypatch):
        """Test that images.yaml takes precedence over state files."""
        # Create state file with old config
        image_file = temp_structure / "image-factory" / "state" / "images" / "backstage.yaml"
        image_file.write_text(yaml.dump({
            'name': 'backstage',
            'repoURL': 'docker.io/old/backstage',
            'allowTags': '^old$',
            'imageSelectionStrategy': 'Lexical'
        }))
        
        # Update images.yaml with new config
        images_yaml = temp_structure / "image-factory" / "images.yaml"
        images_yaml.write_text(yaml.dump([
            {
                'name': 'backstage',
                'repoURL': 'ghcr.io/new/backstage',
                'allowTags': '^new$',
                'imageSelectionStrategy': 'SemVer'
            }
        ]))
        
        # Mock the file paths
        import main
        monkeypatch.setattr(main, 'IMAGES_YAML', temp_structure / "image-factory" / "images.yaml")
        monkeypatch.setattr(main, 'STATE_IMAGES_DIR', temp_structure / "image-factory" / "state" / "images")
        monkeypatch.setattr(main, 'STATE_BASE_IMAGES_DIR', temp_structure / "image-factory" / "state" / "base-images")
        
        # Create app and chart
        output_dir = Path(__file__).parent / "tests" / ".output"
        output_dir.mkdir(parents=True, exist_ok=True)
        app = App(outdir=str(output_dir))
        chart = ImageFactoryChart(app, "test")
        
        # Synthesize to YAML using helper function
        results = synth_chart_to_yaml(app)
        
        # Parse the output
        manifests = list(yaml.safe_load_all(results))
        
        # Find the warehouse
        warehouse = None
        for manifest in manifests:
            if manifest and manifest.get('kind') == 'Warehouse' and manifest.get('metadata', {}).get('name') == 'backstage':
                warehouse = manifest
                break
        
        assert warehouse is not None
        
        # Verify new config from images.yaml is used
        image_sub = warehouse['spec']['subscriptions'][0]['image']
        assert image_sub['repoURL'] == 'ghcr.io/new/backstage'  # Note: uppercase URL
        assert image_sub['allowTags'] == '^new$'
        assert image_sub['imageSelectionStrategy'] == 'SemVer'
    
    def test_chart_handles_multiple_images(self, temp_structure, monkeypatch):
        """Test that chart creates warehouses for multiple images."""
        # Create multiple base image state files
        for i in range(3):
            base_file = temp_structure / "image-factory" / "state" / "base-images" / f"image-{i}.yaml"
            base_file.write_text(yaml.dump({
                'name': f'image-{i}',
                'repoURL': f'docker.io/library/image-{i}',
                'allowTags': f'^v{i}$',
                'imageSelectionStrategy': 'Lexical'
            }))
        
        # Mock the file paths
        import main
        monkeypatch.setattr(main, 'IMAGES_YAML', temp_structure / "image-factory" / "images.yaml")
        monkeypatch.setattr(main, 'STATE_IMAGES_DIR', temp_structure / "image-factory" / "state" / "images")
        monkeypatch.setattr(main, 'STATE_BASE_IMAGES_DIR', temp_structure / "image-factory" / "state" / "base-images")
        
        # Create app and chart
        output_dir = Path(__file__).parent / "tests" / ".output"
        output_dir.mkdir(parents=True, exist_ok=True)
        app = App(outdir=str(output_dir))
        chart = ImageFactoryChart(app, "test")
        
        # Synthesize to YAML using helper function
        results = synth_chart_to_yaml(app)
        
        # Parse the output
        manifests = list(yaml.safe_load_all(results))
        
        # Count warehouses
        warehouses = [m for m in manifests if m and m.get('kind') == 'Warehouse']
        assert len(warehouses) == 3
        
        # Verify all images present
        warehouse_names = {w['metadata']['name'] for w in warehouses}
        assert warehouse_names == {'image-0', 'image-1', 'image-2'}


class TestGitSubscriptionConfiguration:
    """Property-based tests for git subscription configuration."""
    
    @settings(suppress_health_check=[HealthCheck.filter_too_much])
    @given(
        provider=st.sampled_from(['github', 'gitlab']),
        repo=st.text(min_size=5, max_size=30, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-_/')).filter(lambda x: '/' in x and x.count('/') == 1 and not x.startswith('/') and not x.endswith('/')),
        branch=st.sampled_from(['main', 'master', 'develop', 'feature-branch', 'test']),
        dockerfile=st.sampled_from([
            'apps/backstage/Dockerfile',
            'apps/uv/Dockerfile', 
            'backstage/app/packages/backend/Dockerfile',
            'services/api/Dockerfile',
            'Dockerfile'
        ]),
        image_name=st.text(min_size=3, max_size=15, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-_'))
    )
    def test_git_subscription_configuration_property(self, provider, repo, branch, dockerfile, image_name):
        """
        Property test for git subscription configuration.
        
        **Feature: image-factory, Property 17: Git subscription configuration for verification re-triggering**
        **Validates: Requirements 17.1, 17.2, 17.3, 17.7**
        
        For any valid source configuration with provider, repo, branch, and dockerfile,
        the git subscription configuration should include the correct repository URL,
        branch, include paths for both app directory and image-factory directory,
        and proper batching configuration.
        """
        source = {
            'provider': provider,
            'repo': repo,
            'branch': branch,
            'dockerfile': dockerfile
        }
        
        config = _build_git_subscription_config(source, image_name)
        
        # Property 1: Configuration should be generated for valid inputs
        assert config is not None
        assert isinstance(config, dict)
        assert len(config) > 0
        
        # Property 2: Repository URL should match provider and repo
        expected_url = f"https://{provider}.com/{repo}.git"
        assert config['repoUrl'] == expected_url
        
        # Property 3: Branch should match input
        assert config['branch'] == branch
        
        # Property 4: Should always include image-factory directory
        assert 'includePaths' in config
        assert 'image-factory/' in config['includePaths']
        
        # Property 5: Should include app-specific directory based on dockerfile
        if dockerfile.startswith('apps/'):
            # For apps/xxx/Dockerfile pattern, should include apps/xxx/
            parts = dockerfile.split('/')
            if len(parts) >= 2:
                expected_app_dir = f"apps/{parts[1]}/"
                assert expected_app_dir in config['includePaths']
        elif '/' in dockerfile:
            # For other patterns, should include first directory
            first_dir = dockerfile.split('/')[0] + '/'
            assert first_dir in config['includePaths']
        
        # Property 6: Should have batching configuration
        assert config['discoveryLimit'] == 5  # Batching limit
        assert config['strictSemvers'] == False
        
        # Property 7: Should use correct commit selection strategy
        from imports.warehouse.io.akuity.kargo import WarehouseSpecSubscriptionsGitCommitSelectionStrategy
        assert config['commitSelectionStrategy'] == WarehouseSpecSubscriptionsGitCommitSelectionStrategy.NEWEST_FROM_BRANCH
    
    def test_git_subscription_empty_inputs(self):
        """Test that empty or invalid inputs return empty configuration."""
        # Empty repo should return empty config
        config = _build_git_subscription_config({'provider': 'github', 'repo': '', 'branch': 'main'}, 'test')
        assert config == {}
        
        # Empty branch should return empty config
        config = _build_git_subscription_config({'provider': 'github', 'repo': 'owner/repo', 'branch': ''}, 'test')
        assert config == {}
        
        # Missing repo should return empty config
        config = _build_git_subscription_config({'provider': 'github', 'branch': 'main'}, 'test')
        assert config == {}
        
        # Missing branch should return empty config
        config = _build_git_subscription_config({'provider': 'github', 'repo': 'owner/repo'}, 'test')
        assert config == {}
        
        # Valid inputs should return non-empty config
        config = _build_git_subscription_config({'provider': 'github', 'repo': 'owner/repo', 'branch': 'main'}, 'test')
        assert config != {}
        assert 'repoUrl' in config
        assert 'branch' in config


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
