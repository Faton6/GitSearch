#!/usr/bin/env python3
"""
Test script to verify GraphQL API access with configured tokens.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.logger import logger  # noqa: E402
from src.searcher.graphql_client import get_graphql_client  # noqa: E402


def test_graphql_search():
    """Test GraphQL search functionality."""
    logger.info("=" * 60)
    logger.info("Testing GraphQL API Access")
    logger.info("=" * 60)

    graphql_client = get_graphql_client()

    # Test search query
    query = """
    query TestSearch($query: String!, $first: Int!) {
      search(query: $query, type: REPOSITORY, first: $first) {
        repositoryCount
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          ... on Repository {
            name
            owner {
              login
            }
            url
            stargazerCount
            description
          }
        }
      }
    }
    """

    variables = {"query": "vtb", "first": 3}

    logger.info(f"Executing GraphQL search for: {variables['query']}")

    try:
        data = graphql_client.execute_query(query, variables)

        if data and "data" in data:
            search_results = data["data"].get("search", {})
            repo_count = search_results.get("repositoryCount", 0)
            nodes = search_results.get("nodes", [])

            logger.info("✅ GraphQL search successful!")
            logger.info(f"   Total repositories found: {repo_count}")
            logger.info(f"   Retrieved: {len(nodes)} repositories")

            for i, repo in enumerate(nodes, 1):
                logger.info(f"   {i}. {repo['owner']['login']}/{repo['name']} ⭐ {repo['stargazerCount']}")

            logger.info("\n🎉 GraphQL API is working correctly!")
            logger.info(f"   Tokens with GraphQL access: {len(graphql_client._tokens_with_graphql)}")
            logger.info(f"   Tokens without GraphQL access: {len(graphql_client._tokens_without_graphql)}")

            return True

        elif data and "errors" in data:
            logger.error("❌ GraphQL returned errors:")
            for error in data["errors"]:
                logger.error(f"   - {error.get('message', 'Unknown error')}")
            return False
        else:
            logger.error("❌ Unexpected response format")
            return False

    except Exception as e:
        logger.error(f"❌ Exception during GraphQL test: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_graphql_repo_stats():
    """Test GraphQL repository stats query."""
    logger.info("\n" + "=" * 60)
    logger.info("Testing GraphQL Repository Stats")
    logger.info("=" * 60)

    graphql_client = get_graphql_client()

    query = """
    query GetRepoStats($owner: String!, $name: String!) {
      repository(owner: $owner, name: $name) {
        name
        stargazerCount
        forkCount
        description
        createdAt
        updatedAt
      }
    }
    """

    variables = {"owner": "torvalds", "name": "linux"}

    logger.info(f"Fetching stats for: {variables['owner']}/{variables['name']}")

    try:
        data = graphql_client.execute_query(query, variables)

        if data and "data" in data and "repository" in data["data"]:
            repo = data["data"]["repository"]
            logger.info("✅ Repository stats retrieved successfully!")
            logger.info(f"   Name: {repo['name']}")
            logger.info(f"   Stars: {repo['stargazerCount']}")
            logger.info(f"   Forks: {repo['forkCount']}")
            logger.info(f"   Description: {repo.get('description', 'N/A')[:80]}...")
            return True
        else:
            logger.warning("⚠️  Repository stats query failed (may need additional permissions)")
            return False

    except Exception as e:
        logger.error(f"❌ Exception: {e}")
        return False


if __name__ == "__main__":
    success = test_graphql_search()

    if success:
        test_graphql_repo_stats()

    logger.info("\n" + "=" * 60)
    logger.info("Test completed")
    logger.info("=" * 60)
