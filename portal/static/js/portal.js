/* Patched portal: dependency-free table search, sorting and row filters. */
(function () {
  "use strict";

  /* PAT-2008: everything page-level lives in init(), so the approval flow
     can swap in a freshly rendered <main> after a write and re-run it
     against the new DOM. Nothing in init() binds to document or window;
     those listeners are bound once, further down. */
  function approvalFilterExcludes(row) {
    if (!row.hasAttribute("data-approval-row")) return false;
    var panel = document.querySelector("[data-approval-filters]");
    if (!panel) return false;
    var publisher = panel.querySelector("[data-filter-publisher]");
    var minDevices = panel.querySelector("[data-filter-min-devices]");
    var wanted = publisher ? publisher.value : "";
    var rowPublisher = row.getAttribute("data-publisher") || "";
    if (wanted === "__unknown__" && rowPublisher) return true;
    if (wanted && wanted !== "__unknown__" && rowPublisher !== wanted) return true;
    var min = minDevices ? parseInt(minDevices.value, 10) : NaN;
    if (!isNaN(min) && min > 0 && (parseInt(row.getAttribute("data-devices"), 10) || 0) < min) return true;
    // PAT-2163 (orchestrator follow-up): the old "Unreviewed only" checkbox
    // is gone - Approval = Waiting on a decision (data-row-filter="decision"
    // above) is the identical row set, so this dimension needs no
    // replacement here, only removal.
    return false;
  }

  function init() {

  function dataRows(table) {
    if (!table || !table.tBodies.length) return [];
    return Array.prototype.filter.call(table.tBodies[0].rows, function (row) {
      return !row.classList.contains("row-summary");
    });
  }

  // Summary rows (findings page) follow their parent row; keep them attached.
  function rowGroup(row) {
    var group = [row];
    var next = row.nextElementSibling;
    if (next && next.classList.contains("row-summary")) group.push(next);
    return group;
  }

  function updateEmptyState(table) {
    var scope = table.closest(".group-card, .card") || table.parentElement;
    var empty = scope ? scope.querySelector("[data-filter-empty]") : null;
    if (!empty) return;
    var rows = dataRows(table);
    // A table with no rows at all already carries its own server-rendered
    // "none found" message; "nothing matches this filter" would contradict it.
    if (!rows.length && !empty.hasAttribute("data-empty-roster")) { empty.hidden = true; return; }
    var visible = rows.some(function (row) {
      return !row.classList.contains("row-hide-search") &&
        !row.classList.contains("row-hide-filter");
    });
    empty.hidden = visible;
  }

  function tablesForSearch(input) {
    var selector = input.getAttribute("data-table-search");
    if (selector) return Array.prototype.slice.call(document.querySelectorAll(selector));
    var nearest = input.closest(".group-card, .card, .findings-section");
    if (nearest) return Array.prototype.slice.call(nearest.querySelectorAll(".data-table"));
    return [];
  }

  /* PAT-2255: a row may carry data-search, the lower-cased text the server
     matched the URL's ?search= against (it includes identifiers the list
     no longer shows), so the browser and the first paint filter alike.
     Rows without it fall back to their visible text, as before. A search
     box with data-query-param also keeps the URL in step, so the filtered
     view survives a reload, a shared link and an approval write. */
  function searchText(row) {
    var own = row.getAttribute("data-search");
    return own !== null ? own : row.textContent.toLowerCase();
  }

  Array.prototype.forEach.call(
    document.querySelectorAll("[data-table-search]"),
    function (input) {
      var tables = tablesForSearch(input);
      input.addEventListener("input", function () {
        var q = input.value.trim().toLowerCase();
        tables.forEach(function (table) {
          dataRows(table).forEach(function (row) {
            var show = !q || searchText(row).indexOf(q) !== -1;
            rowGroup(row).forEach(function (related) {
              related.classList.toggle("row-hide-search", !show);
            });
          });
          updateEmptyState(table);
        });
        var param = input.getAttribute("data-query-param");
        if (param && window.history && window.history.replaceState) {
          var url = new URL(window.location.href);
          if (input.value.trim()) url.searchParams.set(param, input.value.trim());
          else url.searchParams.delete(param);
          url.searchParams.delete("approval_result");
          window.history.replaceState(null, "", url.pathname + url.search + url.hash);
        }
        // PAT-2008 review fix (P3): a search (the inventory table's own box
        // included) can hide a row that is still selected; it must not stay
        // selected and be written without the customer noticing.
        clearHiddenSelections();
        if (input.hasAttribute("data-search-filter-chip") && rebuildChips) rebuildChips();
      });
    }
  );

  function cellValue(row, index, kind) {
    var cell = row.cells[index];
    if (!cell) return kind === "num" ? -Infinity : "";
    var raw = cell.getAttribute("data-value");
    if (raw === null) raw = cell.textContent.trim();
    if (kind === "num") {
      var n = parseFloat(raw);
      return isNaN(n) ? -Infinity : n;
    }
    return raw.toLowerCase();
  }

  Array.prototype.forEach.call(document.querySelectorAll(".data-table"), function (table) {
    if (!table.tHead || !table.tHead.rows.length || !table.tBodies.length) return;
    Array.prototype.forEach.call(table.tHead.rows[0].cells, function (th, index) {
      var kind = th.getAttribute("data-sort");
      if (!kind) return;
      th.addEventListener("click", function () {
        var asc = !th.classList.contains("sorted-asc");
        Array.prototype.forEach.call(table.tHead.rows[0].cells, function (heading) {
          heading.classList.remove("sorted-asc", "sorted-desc");
        });
        th.classList.add(asc ? "sorted-asc" : "sorted-desc");
        var rows = dataRows(table);
        rows.sort(function (a, b) {
          var va = cellValue(a, index, kind === "date" ? "text" : kind);
          var vb = cellValue(b, index, kind === "date" ? "text" : kind);
          if (va < vb) return asc ? -1 : 1;
          if (va > vb) return asc ? 1 : -1;
          return 0;
        });
        rows.forEach(function (row) {
          rowGroup(row).forEach(function (related) {
            table.tBodies[0].appendChild(related);
          });
        });
      });
    });
  });

  /* Shared segmented row filters. Each control names the row data attribute
     it owns (for example kind -> data-filter-kind). Every active control is
     evaluated when any one changes, so two filters on one page compose
     instead of removing each other's hidden state. Search remains independent
     through row-hide-search. */
  var filters = Array.prototype.slice.call(document.querySelectorAll("[data-row-filter]"));

  /* PAT-2163: a filter's "selected" state is either a single tab value
     (segmented_control, unchanged) or a comma list (the Approval multi-
     select dropdown) - both stored in the same data-selected/data-initial
     attribute, so this is the one place that has to know the difference.
     "all"/"" means unfiltered, same as before. */
  function selectedValues(filter) {
    var raw = filter.getAttribute("data-selected") ||
      filter.getAttribute("data-initial") || "all";
    if (raw === "all" || raw === "") return null;
    return raw.split(",");
  }

  function applyFilters() {
    var tables = Array.prototype.slice.call(document.querySelectorAll(".data-table"));
    tables.forEach(function (table) {
      dataRows(table).forEach(function (row) {
        var excluded = approvalFilterExcludes(row) || filters.some(function (filter) {
          var name = filter.getAttribute("data-row-filter");
          var rowValue = row.getAttribute("data-filter-" + name);
          if (rowValue === null) return false;
          var values = selectedValues(filter);
          return values !== null && values.indexOf(rowValue) === -1;
        });
        rowGroup(row).forEach(function (related) {
          related.classList.toggle("row-hide-filter", excluded);
        });
      });
      updateEmptyState(table);
    });
  }

  filters.forEach(function (filter) {
    var tabs = Array.prototype.slice.call(filter.querySelectorAll("[data-filter-tab]"));
    if (!tabs.length) return;

    function select(value, updateUrl) {
      filter.setAttribute("data-selected", value);
      tabs.forEach(function (tab) {
        var active = tab.getAttribute("data-filter-tab") === value;
        tab.classList.toggle("tab-active", active);
        if (active) tab.setAttribute("aria-current", "true");
        else tab.removeAttribute("aria-current");
      });
      applyFilters();
      // PAT-2008 review fix (P3): switching the Applications/Extensions/All
      // tab can hide a row that is still selected; it must not stay
      // selected and be written without the customer noticing.
      clearHiddenSelections();

      if (updateUrl && window.history && window.history.replaceState) {
        var parameter = filter.getAttribute("data-query-param");
        if (!parameter) return;
        var url = new URL(window.location.href);
        var defaultValue = filter.getAttribute("data-default-value");
        if (defaultValue && value === defaultValue) url.searchParams.delete(parameter);
        else url.searchParams.set(parameter, value);
        window.history.replaceState(null, "", url.pathname + url.search + url.hash);
      }
    }

    if (!filter.hasAttribute("data-server-navigation")) tabs.forEach(function (tab) {
      tab.addEventListener("click", function (event) {
        event.preventDefault();
        select(tab.getAttribute("data-filter-tab") || "all", true);
      });
    });
    select(filter.getAttribute("data-initial") || "all", false);
  });

  /* PAT-2163 (generalised for any number of dropdowns by PAT-2213 - see
     below): the filter bar idiom (templates/_macros.html's filter_bar,
     and PAT-2213's own ai-tooling filter dropdowns) - a <select> that
     applies instantly on change, and each checkbox <details> popover that
     applies on its own Apply button (batched, so ticking several boxes
     doesn't re-filter - and flicker - on every single click) or a real
     form submit with no JS. All of them write into the same
     data-selected/data-row-filter attributes applyFilters() above already
     reads, single value or comma list alike - see selectedValues().

     PAT-2213: /software has exactly one <select> (Type) and one <details>
     (Approval); /ai-tooling has three <details> dropdowns (Type, State,
     Assessment) and no <select> at all. Rather than hardcode "the Type
     select" and "the Approval dropdown" as this block used to, everything
     below loops over however many row-filter controls a given filter bar
     actually has, so one filter bar component serves both shapes. Chip
     labels are read straight from each control's own rendered option text
     (stripped of its trailing " (N)" count) instead of a hardcoded
     JS-side label map per page, so a JS-rebuilt chip can never drift from
     what the server rendered - the two are always the same one place. */
  var filterBar = document.querySelector("[data-filter-bar]");
  // Declared here (not just inside the block below) so initApprovals's
  // Publisher/More-filters handlers - which fire independently of the
  // row-filter controls above - can also trigger a chip rebuild after
  // PAT-2163's orchestrator follow-up folded Publisher and minimum-devices
  // into the same bar and chip row.
  var rebuildChips = null;
  if (filterBar) {
    var rowFilterEls = Array.prototype.slice.call(
      filterBar.querySelectorAll(
        "select[data-row-filter], details[data-row-filter], fieldset[data-row-filter]"));

    /* PAT-2255: a control whose default is itself a filter (Homebrew's
       install type defaults to "on request", data-default-value=
       "on_request") leaves the URL bare at that default and writes the
       other value ("all") explicitly; a control with an empty default
       behaves exactly as before ("", "all" = no param). */
    function isDefaultValue(el, value) {
      var def = el.getAttribute("data-default-value") || "";
      if (def) return value === def;
      return !value || value === "all";
    }

    var updateFilterUrl = function (filter) {
      if (!window.history || !window.history.replaceState) return;
      var parameter = filter.getAttribute("data-query-param");
      if (!parameter) return;
      var value = filter.getAttribute("data-selected");
      var url = new URL(window.location.href);
      if (isDefaultValue(filter, value)) url.searchParams.delete(parameter);
      else url.searchParams.set(parameter, value);
      // The legacy ?decision= alias only ever seeds the first render - once
      // JS has taken over filtering, the address bar should show the
      // current ?approval= form, not a stale mix of both.
      if (parameter === "approval") url.searchParams.delete("decision");
      window.history.replaceState(null, "", url.pathname + url.search + url.hash);
    };

    function optionLabel(el, value) {
      var text = null;
      if (el.tagName === "SELECT") {
        Array.prototype.forEach.call(el.options, function (opt) {
          if (opt.value === value) text = opt.textContent;
        });
      } else {
        Array.prototype.forEach.call(el.querySelectorAll('input[type="checkbox"]'), function (box) {
          if (box.value === value && box.nextElementSibling) text = box.nextElementSibling.textContent;
        });
      }
      if (text == null) text = value;
      return text.replace(/\s*\(\d+\)\s*$/, "").trim();
    }

    function removeUrl(param, value) {
      var url = new URL(window.location.href);
      url.searchParams.delete("approval_result");
      url.searchParams.delete("notification_result");
      if (value === null) {
        url.searchParams.delete(param);
      } else {
        var rest = (url.searchParams.get(param) || "").split(",").filter(function (v) {
          return v && v !== value;
        });
        if (rest.length) url.searchParams.set(param, rest.join(","));
        else url.searchParams.delete(param);
      }
      return url.pathname + url.search;
    }

    /* Chips are server-rendered from the query string at page load, but an
       instant client-side apply above never reloads the page - so without
       this, the chips row would go stale the moment a customer picks a
       filter without a full navigation. Rebuilds from every control's own
       current data-selected state (already updated by the caller) rather
       than re-reading the URL, so it can never disagree with what just got
       applied to the rows. Each chip's remove_url is computed from the
       *current* address bar (already updated by updateFilterUrl, called
       first by both handlers below), the same "current URL minus one
       value" shape main.py's build_url produces server-side. */
    rebuildChips = function () {
      var wrap = filterBar.querySelector(".filter-chips");
      var chips = [];
      // PAT-2255: a server-rendered chip marked data-chip-static (the
      // review queue, first-seen window and urgency on /software) has no
      // control behind it to rebuild from, so it is kept as rendered, its
      // link refreshed against the current address bar.
      if (wrap) {
        Array.prototype.forEach.call(wrap.querySelectorAll("[data-chip-static]"), function (a) {
          var param = a.getAttribute("data-chip-param");
          if (!param) return;
          var value = a.getAttribute("data-chip-value") || null;
          chips.push({
            label: a.firstChild ? a.firstChild.textContent : "",
            href: removeUrl(param, value),
            isStatic: true, param: param, value: value || "",
          });
        });
      }
      rowFilterEls.forEach(function (el) {
        var parameter = el.getAttribute("data-query-param");
        if (!parameter) return;
        var raw = el.getAttribute("data-selected") || "";
        if (isDefaultValue(el, raw)) return;
        raw.split(",").forEach(function (value) {
          if (!value) return;
          chips.push({ label: optionLabel(el, value), href: removeUrl(parameter, value) });
        });
      });
      // PAT-2163 (orchestrator follow-up): Publisher and minimum-devices
      // are not part of the data-row-filter/data-selected system above -
      // they feed approvalFilterExcludes() straight from these controls'
      // own live values (see initApprovals), so that is what the chip
      // rebuild reads too, rather than a snapshot that could disagree.
      // /ai-tooling has neither control, so this is always a no-op there.
      var publisherEl = document.querySelector("[data-filter-publisher]");
      var publisherValue = publisherEl ? publisherEl.value : "";
      var minDevicesEl = document.querySelector("[data-filter-min-devices]");
      var minDevicesValue = minDevicesEl ? (parseInt(minDevicesEl.value, 10) || 0) : 0;
      if (publisherValue) {
        chips.push({
          label: "Publisher: " + (publisherValue === "__unknown__" ?
            "Publisher not known" : publisherValue),
          href: removeUrl("publisher", null),
        });
      }
      if (minDevicesValue > 0) {
        chips.push({
          label: "At least " + minDevicesValue +
            (minDevicesValue === 1 ? " device" : " devices"),
          href: removeUrl("min_devices", null),
        });
      }

      // AI's GET search field participates in the same removable chip bar.
      var searchInput = filterBar.querySelector("[data-search-filter-chip]");
      if (searchInput && searchInput.value.trim()) {
        chips.push({label: "Search: " + searchInput.value.trim(), href: removeUrl("search", null)});
      }

      if (!chips.length) {
        if (wrap) wrap.remove();
        return;
      }
      if (!wrap) {
        wrap = document.createElement("div");
        wrap.className = "filter-chips";
        wrap.setAttribute("aria-label", "Active filters");
        filterBar.appendChild(wrap);
      }
      wrap.textContent = "";
      chips.forEach(function (chip) {
        var a = document.createElement("a");
        a.className = "filter-chip";
        a.href = chip.href;
        if (chip.isStatic) {
          a.setAttribute("data-chip-static", "");
          a.setAttribute("data-chip-param", chip.param);
          a.setAttribute("data-chip-value", chip.value);
        }
        a.appendChild(document.createTextNode(chip.label));
        var remove = document.createElement("span");
        remove.className = "filter-chip__remove";
        remove.setAttribute("aria-hidden", "true");
        remove.textContent = "×";
        a.appendChild(remove);
        var hidden = document.createElement("span");
        hidden.className = "visually-hidden";
        hidden.textContent = ", remove this filter";
        a.appendChild(hidden);
        wrap.appendChild(a);
      });
      var clearUrl = new URL(window.location.href);
      rowFilterEls.forEach(function (el) {
        var parameter = el.getAttribute("data-query-param");
        if (parameter) clearUrl.searchParams.delete(parameter);
      });
      // PAT-2255: every filter the URL can carry, the /software review
      // queue, first-seen window, urgency and search included, and
      // Homebrew's install type and findings.
      ["decision", "publisher", "min_devices", "unreviewed", "approval_result",
       "notification_result", "new_since", "new_days", "urgency", "search",
       "deps", "findings"].forEach(function (name) {
        clearUrl.searchParams.delete(name);
      });
      var clear = document.createElement("a");
      clear.className = "filter-chip filter-chip--clear";
      clear.href = clearUrl.pathname + clearUrl.search;
      clear.textContent = "Clear all";
      wrap.appendChild(clear);
    };

    var dropdownFilters = [];
    rowFilterEls.forEach(function (el) {
      if (el.tagName === "SELECT") {
        el.addEventListener("change", function () {
          el.setAttribute("data-selected", el.value || "all");
          applyFilters();
          clearHiddenSelections();
          updateFilterUrl(el);
          rebuildChips();
        });
        return;
      }
      /* PAT-2326: a checkbox group that lives inside the "More filters"
         panel (/software's Usage). That panel's Apply is handled by
         initApprovals, which does not read these boxes, so the group
         applies on change the way a <select> does, and writes its own
         URL param. */
      if (el.tagName === "FIELDSET") {
        var groupBoxes = Array.prototype.slice.call(
          el.querySelectorAll('input[type="checkbox"]'));
        groupBoxes.forEach(function (box) {
          box.addEventListener("change", function () {
            var picked = groupBoxes.filter(function (b) { return b.checked; })
              .map(function (b) { return b.value; });
            el.setAttribute("data-selected", picked.length ? picked.join(",") : "all");
            applyFilters();
            clearHiddenSelections();
            updateFilterUrl(el);
            rebuildChips();
          });
        });
        return;
      }
      var boxes = Array.prototype.slice.call(el.querySelectorAll('input[type="checkbox"]'));
      var count = el.querySelector("[data-filter-dropdown-count]");
      var syncCount = function () {
        if (!count) return;
        var n = boxes.filter(function (box) { return box.checked; }).length;
        count.textContent = n ? String(n) : "";
        count.hidden = !n;
      };
      boxes.forEach(function (box) { box.addEventListener("change", syncCount); });
      dropdownFilters.push({
        el: el,
        apply: function () {
          var values = boxes.filter(function (box) { return box.checked; })
            .map(function (box) { return box.value; });
          el.setAttribute("data-selected", values.length ? values.join(",") : "all");
          el.removeAttribute("open");
        },
      });
    });

    // One submit handler per <form>, applying every checkbox dropdown
    // inside it together - so ticking boxes across several dropdowns
    // (Type, State, Assessment) and clicking any one Apply button applies
    // all of them in one go, not just the dropdown whose own button was
    // clicked. On /software this reduces to exactly the old single-
    // Approval-dropdown behaviour, since it has only one.
    var formsSeen = [];
    dropdownFilters.forEach(function (filter) {
      var form = filter.el.closest("form");
      if (!form || formsSeen.indexOf(form) !== -1) return;
      formsSeen.push(form);
      var filtersInForm = dropdownFilters.filter(function (f) {
        return f.el.closest("form") === form;
      });
      form.addEventListener("submit", function (event) {
        event.preventDefault();
        filtersInForm.forEach(function (f) { f.apply(); });
        applyFilters();
        clearHiddenSelections();
        filtersInForm.forEach(function (f) { updateFilterUrl(f.el); });
        rebuildChips();
        var summary = filtersInForm[0].el.querySelector("summary");
        if (summary) summary.focus();
      });
    });

    // PAT-2215: apply every dropdown's server-seeded data-initial state
    // once on load. Without this, a bookmarked or shared filtered link
    // (main.py's own docstrings promise "this only ever seeds which
    // options start checked... so a bookmarked link opens on the right
    // state") pre-checks the right boxes but never actually hides a row
    // until the customer clicks Apply again - on /software and /ai-tooling
    // this went unnoticed only because their own [data-approval-filters]
    // panel happens to call applyFilters() once below for an unrelated
    // reason (initApprovals, further down); a filter-bar page with no
    // approval panel (for example /local-admins, PAT-2215) had no such
    // call at all. Calling it here makes every data-filter-bar page behave
    // the same regardless of whether it also has an approval panel; it is
    // a harmless no-op repeat on the pages that already got it indirectly.
    applyFilters();
  }

    initApprovals(applyFilters, rebuildChips);
  }

  /* ── Approval controls (PAT-2008) ─────────────────────────────────── */
  function rowHidden(input) {
    var row = input.closest("tr");
    return !!row && (row.classList.contains("row-hide-filter") ||
      row.classList.contains("row-hide-search") || row.offsetParent === null);
  }

  function selectedBoxes() {
    return Array.prototype.filter.call(
      document.querySelectorAll("input.approval-select"),
      function (box) { return box.checked; });
  }

  function refreshBulkBar() {
    var bar = document.querySelector("[data-bulk-bar]");
    if (!bar) return;
    var count = selectedBoxes().length;
    var label = bar.querySelector("[data-bulk-count]");
    if (label) {
      label.textContent = count === 0 ? "Select products to mark several at once." :
        count + (count === 1 ? " product selected" : " products selected");
    }
    bar.classList.toggle("is-active", count > 0);
    // PAT-2163 (orchestrator follow-up): js-bulk.is-active is what shows
    // the bar at all now (portal.css) - hidden until something is
    // selected, matching every row's own individual Approve/Apply control
    // that already worked with nothing selected. On a phone the bar is
    // fixed to the viewport bottom while active; this reserves room under
    // the table so its last row is never hidden behind it.
    document.body.classList.toggle("bulk-bar-active", count > 0);
    Array.prototype.forEach.call(bar.querySelectorAll("[data-bulk-submit]"), function (btn) {
      btn.disabled = count === 0;
    });
    var clear = bar.querySelector("[data-bulk-clear]");
    if (clear) clear.hidden = count === 0;
  }

  /* PAT-2008 review fix (P3): a row hidden by the publisher/min-devices
     filters already cleared its own selection on change, but a
     row hidden by switching the Applications/Extensions/All type tab or by
     typing in a search box did not - the checkbox stayed checked and would
     still be submitted even though the customer can no longer see it. Every
     place that can hide a row calls this afterwards. */
  function clearHiddenSelections() {
    selectedBoxes().forEach(function (box) { if (rowHidden(box)) box.checked = false; });
    // PAT-2058: /homebrew has two independently selectable tables (casks,
    // formulae) sharing one bulk bar, so this is every "select all shown"
    // checkbox on the page, not just the first (previously always true on
    // /software's own single table, so this is unchanged there).
    Array.prototype.forEach.call(
      document.querySelectorAll("[data-select-visible]"),
      function (all) { all.checked = false; });
    refreshBulkBar();
  }

  function syncFilterUrl(panel) {
    if (!window.history || !window.history.replaceState) return;
    var url = new URL(window.location.href);
    var publisher = panel.querySelector("[data-filter-publisher]");
    var minDevices = panel.querySelector("[data-filter-min-devices]");
    function set(name, value) {
      if (value) url.searchParams.set(name, value); else url.searchParams.delete(name);
    }
    set("publisher", publisher ? publisher.value : "");
    var min = minDevices ? parseInt(minDevices.value, 10) : NaN;
    set("min_devices", !isNaN(min) && min > 0 ? String(min) : "");
    // PAT-2163 (orchestrator follow-up): the old "Unreviewed only" checkbox
    // is gone; ?unreviewed=1 only ever seeds the first render (main.py's
    // _software_approval_filter folds it into ?approval=waiting) - once
    // JS has taken over, drop the stale legacy param the same way the
    // Type/Approval controls already drop their own legacy ?decision=.
    url.searchParams.delete("unreviewed");
    url.searchParams.delete("approval_result");
    window.history.replaceState(null, "", url.pathname + url.search);
  }

  function initApprovals(applyFilters, rebuildChips) {
    var panel = document.querySelector("[data-approval-filters]");
    if (panel) {
      var onChange = function () {
        applyFilters();
        // A row a filter hides can no longer be seen, so it must not stay
        // selected and be written without the customer noticing.
        clearHiddenSelections();
        syncFilterUrl(panel);
        if (rebuildChips) rebuildChips();
      };
      Array.prototype.forEach.call(
        panel.querySelectorAll("[data-filter-publisher]"),
        function (el) { el.addEventListener("change", onChange); });
      // PAT-2163 (orchestrator follow-up): minimum-devices moved from an
      // instant per-keystroke filter into the "More filters" popover,
      // batched behind its own Apply button - same shape as the Approval
      // popover's, and reusing the same onChange (applyFilters +
      // clearHiddenSelections + syncFilterUrl + rebuildChips) rather than
      // a bespoke handler.
      var moreFilters = panel.querySelector("details[data-more-filters]");
      if (moreFilters) {
        var moreApply = moreFilters.querySelector("[data-filter-dropdown-apply]");
        if (moreApply) {
          moreApply.addEventListener("click", function (event) {
            event.preventDefault();
            onChange();
            moreFilters.removeAttribute("open");
            var summary = moreFilters.querySelector("summary");
            if (summary) summary.focus();
          });
        }
      }
      // PAT-2163 (orchestrator follow-up): "Select all shown" moved out of
      // this filters panel into the table's own select column header - a
      // document-wide lookup, not panel-scoped, since it no longer lives
      // inside [data-approval-filters].
      // PAT-2058: /homebrew's casks and formulae tables each carry their
      // own "select all shown" checkbox under the one shared bulk bar, so
      // every checkbox is wired (not just the first) and each one only
      // selects rows in its own table - closest("table") finds the same
      // single table a lone checkbox always did, so /software's behaviour
      // is unchanged.
      Array.prototype.forEach.call(
        document.querySelectorAll("[data-select-visible]"),
        function (all) {
          all.addEventListener("change", function () {
            var scope = all.closest("table") || document;
            Array.prototype.forEach.call(
              scope.querySelectorAll("tr[data-approval-row] input.approval-select"),
              function (box) { box.checked = all.checked && !rowHidden(box); });
            refreshBulkBar();
          });
        });
      applyFilters();
    }
    Array.prototype.forEach.call(document.querySelectorAll("input.approval-select"), function (box) {
      box.addEventListener("change", refreshBulkBar);
    });
    var bar = document.querySelector("[data-bulk-bar]");
    if (bar) {
      bar.classList.add("js-bulk");
      var clear = bar.querySelector("[data-bulk-clear]");
      if (clear) {
        clear.addEventListener("click", function () {
          selectedBoxes().forEach(function (box) { box.checked = false; });
          Array.prototype.forEach.call(
            document.querySelectorAll("[data-select-visible]"),
            function (allBox) { allBox.checked = false; });
          refreshBulkBar();
        });
      }
    }
    refreshBulkBar();
    // An inventory row's Apply stays disabled until a state is chosen, so a
    // stray click can never approve anything (the server refuses "" too).
    Array.prototype.forEach.call(document.querySelectorAll("[data-approval-row-form]"), function (rowForm) {
      var select = rowForm.querySelector("[data-approval-row-state]");
      var apply = rowForm.querySelector("[data-approval-row-apply]");
      if (!select || !apply) return;
      var sync = function () { apply.disabled = !select.value; };
      select.addEventListener("change", sync);
      sync();
    });
    var notice = document.querySelector("[data-approval-result]");
    if (notice) {
      notice.classList.add("is-toast");
      var close = notice.querySelector("[data-approval-result-close]");
      if (close) {
        close.hidden = false;
        close.addEventListener("click", function () { notice.remove(); });
      }
    }
  }

  function formBody(form, submitter) {
    var data;
    try {
      data = new FormData(form, submitter);
    } catch (e) {
      data = new FormData(form);
      if (submitter && submitter.name) data.append(submitter.name, submitter.value);
    }
    var params = new URLSearchParams();
    data.forEach(function (value, key) { params.append(key, value); });
    return params;
  }

  /* PAT-2255 review flow: after a write the customer stays on the same
     filtered view with the next product in view. The form carries the id
     of the next row still visible (skipping any being written), which the
     server puts on the redirect as the fragment for a no-JS browser; here,
     after the fresh page is swapped in at the same scroll position, that
     row is scrolled into view only if it is not already on screen. */
  var pendingAnchor = "";

  function rowOutOfView(tr, skip) {
    return !tr.id || skip.indexOf(tr) !== -1 ||
      tr.classList.contains("row-hide-filter") || tr.classList.contains("row-hide-search") ||
      tr.offsetParent === null;
  }

  function nextVisibleRowId(row, skip) {
    if (!row) return "";
    var sib = row.nextElementSibling;
    while (sib) {
      if (!rowOutOfView(sib, skip)) return sib.id;
      sib = sib.nextElementSibling;
    }
    sib = row.previousElementSibling;
    while (sib) {
      if (!rowOutOfView(sib, skip)) return sib.id;
      sib = sib.previousElementSibling;
    }
    return "";
  }

  function bringAnchorIntoView() {
    if (!pendingAnchor) return;
    var target = document.getElementById(pendingAnchor);
    pendingAnchor = "";
    if (!target || target.offsetParent === null) return;
    var rect = target.getBoundingClientRect();
    if (rect.top < 0 || rect.bottom > window.innerHeight) {
      target.scrollIntoView({ block: "center" });
    }
  }

  function swapMain(html, url, redirected) {
    var doc = new DOMParser().parseFromString(html, "text/html");
    var fresh = doc.querySelector("main.page");
    var current = document.querySelector("main.page");
    if (!fresh || !current) {
      window.location.href = url;
      return;
    }
    var y = window.scrollY;
    current.replaceWith(fresh);
    if (redirected && window.history && window.history.replaceState) {
      var next = new URL(url);
      next.searchParams.delete("approval_result");
      window.history.replaceState(null, "", next.pathname + next.search);
    }
    init();
    window.scrollTo(0, y);
    bringAnchorIntoView();
    var notice = document.querySelector("[data-approval-result]");
    if (notice) notice.focus({ preventScroll: true });
  }

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!form || !window.fetch || !window.DOMParser) return;
    var rowForm = form.hasAttribute && form.hasAttribute("data-approval-row-form");
    if (form.id !== "approval-form" && !rowForm) return;
    var submitter = event.submitter || null;
    var isRow = !!(submitter && submitter.name === "row_action");
    var state = "";
    var protectedHit = false;
    if (rowForm) {
      var select = form.querySelector("select[name='state']");
      state = select ? select.value : "";
      if (!state) { event.preventDefault(); return; }
      protectedHit = form.hasAttribute("data-protected");
    } else if (isRow) {
      try { state = JSON.parse(submitter.value).state; } catch (e) { state = ""; }
      protectedHit = submitter.hasAttribute("data-protected");
    } else {
      state = submitter ? submitter.value : "";
      if (!selectedBoxes().length) { event.preventDefault(); return; }
      protectedHit = selectedBoxes().some(function (box) { return box.hasAttribute("data-protected"); });
    }
    if (state === "unapproved" && protectedHit &&
        !window.confirm("This includes a protected product. Marking it Unapproved flags it " +
          "as not wanted, and people using it will see a notice. Continue?")) {
      event.preventDefault();
      return;
    }
    event.preventDefault();
    // The one-line inventory form shares the bulk bar's optional reason.
    var bulkReason = document.querySelector("#approval-form input[name='reason']");
    var back = form.querySelector("[data-approval-return]");
    if (back) {
      var here = new URL(window.location.href);
      here.searchParams.delete("approval_result");
      back.value = here.pathname + here.search;
    }
    var anchorInput = form.querySelector("[data-approval-anchor]");
    var anchorId = "";
    if (rowForm) {
      var actedRow = form.closest("tr");
      anchorId = nextVisibleRowId(actedRow, actedRow ? [actedRow] : []);
    } else if (!isRow) {
      var picked = selectedBoxes().map(function (box) { return box.closest("tr"); });
      anchorId = nextVisibleRowId(picked[picked.length - 1] || null, picked);
    }
    if (anchorInput) anchorInput.value = anchorId;
    pendingAnchor = anchorId;
    var body = formBody(form, submitter);
    if (isRow) body.delete("item");
    if (rowForm && bulkReason && bulkReason.value.trim()) body.set("reason", bulkReason.value);
    Array.prototype.forEach.call(document.querySelectorAll(
      "#approval-form button, button[form='approval-form'], [data-approval-row-form] button"),
      function (btn) { btn.disabled = true; });
    document.documentElement.classList.add("is-busy");
    window.fetch(form.action, {
      method: "POST",
      body: body,
      credentials: "same-origin",
      referrerPolicy: "same-origin",
      headers: { "Content-Type": "application/x-www-form-urlencoded" }
    }).then(function (resp) {
      return resp.text().then(function (html) { swapMain(html, resp.url, resp.redirected); });
    }).catch(function () {
      // PAT-2008 review fix (P3): this used to re-submit the form
      // (form.submit()), but that drops the submitter - the bulk state
      // button or the inline row_action value - so it can silently post a
      // different, wrong action, or none at all. It also fires just as
      // often when the write itself already succeeded and only the
      // redirected GET failed (a slow reload, or a Cloudflare Access
      // session that expired in between), in which case resubmitting would
      // repeat the write. Reload instead: this only ever re-reads the
      // current page, never resubmits a write.
      window.location.reload();
    }).then(function () {
      document.documentElement.classList.remove("is-busy");
    });
  });

  /* History drawer: loads one product's history into the side panel. The
     link itself is a normal page, so it works without JavaScript. */
  var lastTrigger = null;
  function closeDrawer() {
    var panel = document.querySelector("[data-history-panel]");
    if (!panel || panel.hidden) return;
    panel.hidden = true;
    if (lastTrigger && document.body.contains(lastTrigger)) lastTrigger.focus();
  }
  document.addEventListener("click", function (event) {
    var closer = event.target.closest && event.target.closest("[data-history-close]");
    if (closer) { closeDrawer(); return; }
    var link = event.target.closest && event.target.closest("a[data-history-drawer]");
    var panel = document.querySelector("[data-history-panel]");
    if (!link || !panel || !window.fetch) return;
    event.preventDefault();
    lastTrigger = link;
    var body = panel.querySelector("[data-history-body]");
    body.textContent = "Loading history...";
    panel.hidden = false;
    var closeBtn = panel.querySelector("[data-history-close]");
    if (closeBtn) closeBtn.focus();
    var url = link.getAttribute("href") + "&partial=1";
    window.fetch(url, { credentials: "same-origin" }).then(function (resp) {
      if (resp.redirected || !resp.ok) throw new Error("history " + resp.status);
      return resp.text();
    }).then(function (html) {
      // Server-rendered, autoescaped fragment from this origin.
      body.innerHTML = html;
    }).catch(function () {
      body.textContent = "History could not be loaded just now. Try again in a minute.";
    });
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") closeDrawer();
  });

  /* PAT-2163: the Approval filter dropdown (any <details data-filter-
     dropdown>, so this covers a future page that reuses the filter_bar
     macro too) closes on Escape and on a click outside it - added once at
     document level (like the drawer's own Escape handler above) rather
     than inside init(), since these listen for events anywhere on the
     page, not just within the swapped <main> content init() re-binds. */
  document.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") return;
    Array.prototype.forEach.call(
      document.querySelectorAll("details[data-filter-dropdown][open]"),
      function (details) { details.removeAttribute("open"); });
  });
  document.addEventListener("click", function (event) {
    Array.prototype.forEach.call(
      document.querySelectorAll("details[data-filter-dropdown][open]"),
      function (details) {
        if (!details.contains(event.target)) details.removeAttribute("open");
      });
  });

  init();
})();
