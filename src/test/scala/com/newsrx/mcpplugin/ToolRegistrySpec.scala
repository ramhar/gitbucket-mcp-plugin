package com.newsrx.mcpplugin

import com.fasterxml.jackson.databind.ObjectMapper
import com.newsrx.mcpplugin.mcp.ToolRegistry
import org.junit.runner.RunWith
import org.scalatestplus.junit.JUnitRunner
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import scala.jdk.CollectionConverters._

/**
 * Offline controls for what the registry publishes. These run without a
 * GitBucket instance or a database, so they check the surface a client
 * discovers, not the behaviour of a tool against real data. Behavioural
 * controls for authorization, read-back and the ready transition need a live
 * instance and are listed in README.md under "Checks not executed here".
 */
@RunWith(classOf[JUnitRunner])
class ToolRegistrySpec extends AnyFunSuite with Matchers {

  private val mapper = new ObjectMapper()

  test("every registered tool has a unique name and a non-empty description") {
    val tools = ToolRegistry.all(mapper)
    val names = tools.map(_.name)
    names.distinct.size shouldBe names.size
    tools.foreach { t =>
      withClue(s"tool ${t.name}: ") {
        t.name.trim should not be empty
        t.description.trim should not be empty
      }
    }
  }

  test("the operations this increment adds are discoverable") {
    val names = ToolRegistry.all(mapper).map(_.name).toSet
    // Named individually rather than by count, so adding an unrelated tool
    // cannot make this pass while one of these is missing.
    names should contain allOf (
      "whoami",
      "get_thread_comments",
      "update_pull_request",
      "update_own_comment",
      "mark_ready_for_review"
    )
  }

  test("the pre-existing tools are still published") {
    val names = ToolRegistry.all(mapper).map(_.name).toSet
    names should contain allOf (
      "list_pull_requests", "get_pull_request", "add_pr_comment",
      "close_pull_request", "reopen_pull_request", "get_pr_diff",
      "list_issues", "get_issue", "create_issue",
      "close_issue", "reopen_issue", "add_issue_comment",
      "list_repositories", "get_repository"
    )
  }

  test("every input schema is an object schema with a required array") {
    ToolRegistry.all(mapper).foreach { t =>
      val schema = t.inputSchema(mapper)
      withClue(s"tool ${t.name}: ") {
        schema.get("type").asText() shouldBe "object"
        schema.has("properties") shouldBe true
        schema.get("required").isArray shouldBe true
      }
    }
  }

  test("every declared required argument exists among the schema properties") {
    ToolRegistry.all(mapper).foreach { t =>
      val schema = t.inputSchema(mapper)
      val props = schema.get("properties").fieldNames().asScala.toSet
      val required = schema.get("required").elements().asScala.map(_.asText()).toSet
      withClue(s"tool ${t.name}: ") {
        (required diff props) shouldBe empty
      }
    }
  }

  test("whoami takes no required arguments") {
    val tool = ToolRegistry.find("whoami", mapper).getOrElse(fail("whoami is not registered"))
    tool.inputSchema(mapper).get("required").size() shouldBe 0
  }

  test("mark_ready_for_review offers expected_head_sha but does not demand it") {
    val tool = ToolRegistry
      .find("mark_ready_for_review", mapper)
      .getOrElse(fail("mark_ready_for_review is not registered"))
    val schema = tool.inputSchema(mapper)
    schema.get("properties").has("expected_head_sha") shouldBe true
    val required = schema.get("required").elements().asScala.map(_.asText()).toSet
    required should not contain "expected_head_sha"
  }

  test("update_pull_request requires neither title nor body in its schema") {
    // Either one alone is a valid edit, so the schema cannot demand both; the
    // "at least one" rule is enforced in execute and is not expressible here.
    val tool = ToolRegistry
      .find("update_pull_request", mapper)
      .getOrElse(fail("update_pull_request is not registered"))
    val required = tool.inputSchema(mapper).get("required").elements().asScala.map(_.asText()).toSet
    required shouldBe Set("owner", "repo", "number")
  }

  test("the shipped descriptor carries the version the server reports") {
    // v0.1.1 shipped with a descriptor saying 0.1.0 and a separate hardcoded
    // literal in the controller. The version now has one source; this fails if
    // the descriptor is missing from the test classpath or left empty.
    PluginDescriptor.get("pluginVersion").trim should not be empty
    PluginDescriptor.get("pluginId") shouldBe "mcp-plugin"
  }
}
