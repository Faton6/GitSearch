"""
GraphQL Query Batcher for GitHub API.

Combines multiple GraphQL queries into a single request to reduce API calls.
GitHub GraphQL API allows multiple queries in one request using aliases.

Features:
- Batch multiple queries into one request
- Automatic alias generation
- Response parsing and distribution
- Cost tracking
- Rate limit optimization
"""

import time
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
import threading
from queue import Queue, Empty

from src.logger import logger


@dataclass
class BatchedQuery:
    """A single query to be batched."""

    query_id: str
    query: str
    variables: Dict[str, Any]
    callback: Optional[Callable] = None
    created_at: float = field(default_factory=time.time)


@dataclass
class BatchConfig:
    """Configuration for query batching."""

    max_batch_size: int = 5  # Max queries per batch
    max_wait_time: float = 1.0  # Max seconds to wait before sending batch
    max_cost: int = 1000  # Max cost per batch (GitHub limit is 5000)


class GraphQLBatcher:
    """
    Batches multiple GraphQL queries into single requests.

    Usage:
        batcher = GraphQLBatcher()

        # Add queries to batch
        future1 = batcher.add_query(query1, variables1)
        future2 = batcher.add_query(query2, variables2)

        # Results are returned via futures
        result1 = future1.result()
        result2 = future2.result()
    """

    def __init__(self, graphql_client, config: Optional[BatchConfig] = None):
        """
        Initialize batcher.

        Args:
            graphql_client: GraphQL client to execute requests
            config: Batch configuration
        """
        self.client = graphql_client
        self.config = config or BatchConfig()

        self._query_queue: Queue[BatchedQuery] = Queue()
        self._results: Dict[str, Any] = {}
        self._result_events: Dict[str, threading.Event] = {}
        self._lock = threading.RLock()
        self._query_counter = 0

        self._should_stop = False
        self._batch_thread = threading.Thread(target=self._batch_loop, daemon=True, name="GraphQLBatcher")
        self._batch_thread.start()

        self._stats = {"queries_batched": 0, "batches_sent": 0, "total_cost_saved": 0}

        logger.info(
            f"GraphQL batcher started: "
            f"max_batch_size={self.config.max_batch_size}, "
            f"max_wait_time={self.config.max_wait_time}s"
        )

    def add_query(self, query: str, variables: Dict[str, Any], callback: Optional[Callable] = None) -> "QueryFuture":
        """
        Add query to batch.

        Args:
            query: GraphQL query string
            variables: Query variables
            callback: Optional callback when result is ready

        Returns:
            QueryFuture to get result
        """
        with self._lock:
            query_id = f"q{self._query_counter}"
            self._query_counter += 1

            # Create event for this query
            event = threading.Event()
            self._result_events[query_id] = event

            batched_query = BatchedQuery(query_id=query_id, query=query, variables=variables, callback=callback)

            self._query_queue.put(batched_query)

            return QueryFuture(query_id, self, event)

    def _batch_loop(self):
        """Background thread that creates and sends batches."""
        while not self._should_stop:
            try:
                # Collect queries for batch
                batch = []
                batch_start = time.time()

                while len(batch) < self.config.max_batch_size:
                    # Calculate remaining wait time
                    elapsed = time.time() - batch_start
                    remaining_wait = max(0, self.config.max_wait_time - elapsed)

                    if remaining_wait <= 0 and batch:
                        # Time's up, send what we have
                        break

                    try:
                        timeout = remaining_wait if batch else None
                        query = self._query_queue.get(timeout=timeout)
                        batch.append(query)
                    except Empty:
                        # Timeout, send batch if we have queries
                        if batch:
                            break
                        continue

                # Send batch if we have queries
                if batch:
                    self._send_batch(batch)

            except Exception as e:
                logger.error(f"Error in batch loop: {e}")
                time.sleep(1)

    def _send_batch(self, batch: List[BatchedQuery]):
        """
        Send batch of queries as single request.

        Args:
            batch: List of queries to batch
        """
        try:
            logger.debug(f"Sending batch of {len(batch)} queries")

            if len(batch) == 1:
                # Single query, no need for aliasing
                query = batch[0]
                result = self.client.execute_query(query.query, query.variables)
                self._store_result(query.query_id, result)
            else:
                # Multiple queries, need to batch with aliases
                batched_query = self._create_batched_query(batch)
                result = self.client.execute_query(batched_query, {})

                # Parse and distribute results
                if result and "data" in result:
                    for query in batch:
                        # Extract result for this query using alias
                        query_result = result["data"].get(query.query_id, {})
                        self._store_result(query.query_id, {"data": query_result})

            # Update stats
            with self._lock:
                self._stats["queries_batched"] += len(batch)
                self._stats["batches_sent"] += 1
                # Cost saved = (queries - 1) since we made 1 request instead of N
                self._stats["total_cost_saved"] += len(batch) - 1

            logger.debug(f"Batch completed: {len(batch)} queries")

        except Exception as e:
            logger.error(f"Error sending batch: {e}")
            # Store error for all queries in batch
            for query in batch:
                self._store_result(query.query_id, {"error": str(e)})

    def _create_batched_query(self, batch: List[BatchedQuery]) -> str:
        """
        Create single GraphQL query with aliases for multiple queries.

        Args:
            batch: List of queries to combine

        Returns:
            Combined GraphQL query string
        """
        # Extract query bodies and add aliases
        query_parts = []

        for query in batch:
            # Parse query to extract operation
            query_body = query.query.strip()

            # Remove 'query' or 'mutation' keyword if present
            if query_body.startswith("query"):
                query_body = query_body[5:].strip()
            elif query_body.startswith("mutation"):
                query_body = query_body[8:].strip()

            # Remove operation name if present
            if query_body.startswith("("):
                # Has variables, keep them
                pass
            elif " " in query_body:
                # Has operation name, remove it
                query_body = query_body.split(" ", 1)[1]

            # Add alias
            aliased_query = f"{query.query_id}: {query_body}"
            query_parts.append(aliased_query)

        # Combine into single query
        combined = "query {\n  " + "\n  ".join(query_parts) + "\n}"

        return combined

    def _store_result(self, query_id: str, result: Any):
        """
        Store result and notify waiting threads.

        Args:
            query_id: Query identifier
            result: Query result
        """
        with self._lock:
            self._results[query_id] = result

            # Notify waiting thread
            if query_id in self._result_events:
                self._result_events[query_id].set()

            # Call callback if provided
            batched_query = next((q for q in list(self._query_queue.queue) if q.query_id == query_id), None)
            if batched_query and batched_query.callback:
                try:
                    batched_query.callback(result)
                except Exception as e:
                    logger.error(f"Error in callback for {query_id}: {e}")

    def get_result(self, query_id: str, timeout: Optional[float] = None) -> Any:
        """
        Get result for query.

        Args:
            query_id: Query identifier
            timeout: Max seconds to wait

        Returns:
            Query result

        Raises:
            TimeoutError: If timeout exceeded
        """
        # Wait for result
        event = self._result_events.get(query_id)
        if event:
            if not event.wait(timeout=timeout):
                raise TimeoutError(f"Query {query_id} timed out")

        # Get result
        with self._lock:
            result = self._results.pop(query_id, None)
            self._result_events.pop(query_id, None)

        return result

    def get_stats(self) -> Dict[str, int]:
        """Get batching statistics."""
        with self._lock:
            return self._stats.copy()

    def shutdown(self):
        """Shutdown batcher."""
        logger.info("Shutting down GraphQL batcher")
        self._should_stop = True

        if self._batch_thread.is_alive():
            self._batch_thread.join(timeout=5)

        stats = self.get_stats()
        logger.info(
            f"Batcher stats:\n"
            f"  Queries batched: {stats['queries_batched']}\n"
            f"  Batches sent: {stats['batches_sent']}\n"
            f"  Cost saved: {stats['total_cost_saved']}\n"
            f"  Avg batch size: {stats['queries_batched'] / max(stats['batches_sent'], 1):.1f}"
        )


class QueryFuture:
    """Future-like object for batched query result."""

    def __init__(self, query_id: str, batcher: GraphQLBatcher, event: threading.Event):
        self.query_id = query_id
        self.batcher = batcher
        self.event = event
        self._result = None
        self._retrieved = False

    def result(self, timeout: Optional[float] = None) -> Any:
        """
        Get query result (blocks until available).

        Args:
            timeout: Max seconds to wait

        Returns:
            Query result
        """
        if not self._retrieved:
            self._result = self.batcher.get_result(self.query_id, timeout)
            self._retrieved = True
        return self._result

    def done(self) -> bool:
        """Check if result is ready."""
        return self.event.is_set()


# Global batcher instance
_batcher: Optional[GraphQLBatcher] = None


def get_graphql_batcher() -> GraphQLBatcher:
    """Get or create global GraphQL batcher."""
    global _batcher
    if _batcher is None:
        from src.searcher.graphql_client import get_graphql_client

        client = get_graphql_client()
        _batcher = GraphQLBatcher(client)
    return _batcher


def shutdown_batcher():
    """Shutdown global batcher."""
    global _batcher
    if _batcher is not None:
        _batcher.shutdown()
        _batcher = None
