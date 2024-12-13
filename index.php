<?php
declare(strict_types=1);
require_once 'conn.php';
require_once 'kita.php';

function export()
{
    middleware();
    header('Content-Type: text/csv');
    header('Content-Disposition: attachment;filename="vulnerabilities.csv"');
    $output = fopen('php://output', 'w');
    fputcsv($output, array('ID', 'Title', 'Description', 'Severity', 'Reported Date', 'Status'));
    $conn = conn();
    $stmt = $conn->query("SELECT * FROM vulnerabilities");
    while ($row = $stmt->fetch_assoc()) {
        fputcsv($output, $row);
    }
    fclose($output);
}

function store()
{
    middleware();
global $conn;
    $stmt = $conn->prepare("INSERT INTO vulnerabilities (title, description, severity, status) VALUES (?, ?, ?, ?)");
    $stmt->bind_param('ssss', $_POST['title'], $_POST['description'], $_POST['severity'], $_POST['status']);
    $stmt->execute();
    $stmt->close();
    $conn->close();
    returntohome();
}

function returntohome()
{
    header('Location: /');
    exit();
}

function create()
{
    middleware();
    echo '<form method="post" action="/s">';
    echo '<input type="text" name="title" placeholder="Title" required>';
    echo '<textarea name="description" placeholder="Description" required></textarea>';
    echo '<select name="severity">';
    echo '<option value="Low">Low</option>';
    echo '<option value="Medium">Medium</option>';
    echo '<option value="High">High</option>';
    echo '</select>';
    echo '<select name="status">';
    echo '<option value="Open">Open</option>';
    echo '<option value="Closed">Closed</option>';
    echo '</select>';
    echo '<button type="submit">Submit</button>';
    echo '</form>';
}

function importform()
{
    middleware();
    echo '<!DOCTYPE html>
    <html>
    <head>
        <title>Import CSV</title>
    </head>
    <body>
        <form method="post" enctype="multipart/form-data">
            <input type="file" name="csvfile" accept=".csv" required>
            <button type="submit">Upload and Import</button>
        </form>
    </body>
    </html>';
}

function import()
{
    middleware();
    if (!isset($_FILES['csvfile'])) {
        echo "No file uploaded.";
        return;
    }

    $file = $_FILES['csvfile']['tmp_name'];
    $handle = fopen($file, 'r');
    if ($handle === FALSE) {
        echo "Error opening the file.";
        return;
    }

    fgetcsv($handle); // Skip the header row
    $conn = conn();
    $stmt = $conn->prepare("INSERT INTO vulnerabilities (title, description, severity, status) VALUES (?, ?, ?, ?)");

    while (($data = fgetcsv($handle)) !== FALSE) {
        $title = $data[1];          // Assuming the columns match the order: ID, Title, Description, Severity, Reported Date, Status
        $description = $data[2];
        $severity = $data[3];
        $status = $data[5];
        $stmt->bind_param('ssss', $title, $description, $severity, $status);
        $stmt->execute();
    }

    fclose($handle);
    $stmt->close();
    $conn->close();
    echo "CSV data imported successfully!";
}

function editForm($id)
{
    middleware();
    $id = intval($id);
global $conn;
    $result = $conn->query("SELECT * FROM vulnerabilities WHERE id = $id");

    if ($result->num_rows === 0) {
        returntohome();
    }

    $vulnerability = $result->fetch_assoc();
?>
    <!DOCTYPE html>
    <html lang="en">

    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Edit Vulnerability</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    </head>

    <body>
        <div class="container">
            <h2>Edit Vulnerability</h2>
            <form method="post" action="/u/<?php echo $vulnerability['id']; ?>" enctype="application/x-www-form-urlencoded" onsubmit="event.preventDefault(); fetch(this.action, { method: 'PUT', body: new URLSearchParams(new FormData(this)) }).then(response => { if (response.ok) { window.location.href = '/'; } else { alert('Failed to update vulnerability'); } });">
                <div class="form-group">
                    <label for="title">Title</label>
                    <input type="text" class="form-control" id="title" name="title" value="<?php echo htmlspecialchars($vulnerability['title']); ?>" required>
                </div>
                <div class="form-group">
                    <label for="description">Description</label>
                    <textarea class="form-control" id="description" name="description" required><?php echo htmlspecialchars($vulnerability['description']); ?></textarea>
                </div>
                <div class="form-group">
                    <label for="severity">Severity</label>
                    <select class="form-control" id="severity" name="severity">
                        <option value="Low" <?php echo ($vulnerability['severity'] == 'Low') ? 'selected' : ''; ?>>Low</option>
                        <option value="Medium" <?php echo ($vulnerability['severity'] == 'Medium') ? 'selected' : ''; ?>>Medium</option>
                        <option value="High" <?php echo ($vulnerability['severity'] == 'High') ? 'selected' : ''; ?>>High</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="status">Status</label>
                    <select class="form-control" id="status" name="status">
                        <option value="Open" <?php echo ($vulnerability['status'] == 'Open') ? 'selected' : ''; ?>>Open</option>
                        <option value="Closed" <?php echo ($vulnerability['status'] == 'Closed') ? 'selected' : ''; ?>>Closed</option>
                    </select>
                </div>
                <button type="submit" class="btn btn-primary">Save Changes</button>
            </form>
        </div>
    </body>

    </html>
<?php
}

function update($id)
{
    middleware();
    parse_str(file_get_contents("php://input"), $put_vars);
global $conn;
    $stmt = $conn->prepare("UPDATE vulnerabilities SET title = ?, description = ?, severity = ?, status = ? WHERE id = ?");
    $stmt->bind_param('ssssi', $put_vars['title'], $put_vars['description'], $put_vars['severity'], $put_vars['status'], $id);
    $stmt->execute();
    $stmt->close();
    $conn->close();
    exit();
    returntohome();
}

function destroy($id)
{
    middleware();
global $conn;
    $stmt = $conn->prepare("DELETE FROM vulnerabilities WHERE id = ?");
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $stmt->close();
    $conn->close();
    returntohome();
}

function main(): void
{
    connectVuln();
    session_start();
    
    post('/v', 'middleware');
    get('/', 'home');
    get('/e', 'export');
    post('/s', 'store');
    get('/c', 'create');
    get('/if', 'importform');
    post('/i', 'import');
    get('/e/([\w-]+)', 'editForm');
    put('/u/([\w-]+)', 'update');
    delete('/d/([\w-]+)', 'destroy');

}

function home(): void
{
    middleware();
    $limit = 10;
    $page = isset($_GET['page']) ? intval($_GET['page']) : 1;
    $offset = ($page - 1) * $limit;
    $search = isset($_GET['search']) ? trim($_GET['search']) : '';

    // Initialize filters
    $severityFilter = isset($_GET['severity']) && $_GET['severity'] !== '' ? $_GET['severity'] : null;
    $statusFilter = isset($_GET['status']) && $_GET['status'] !== '' ? $_GET['status'] : null;

    // Build the WHERE clause
    $searchSql = ' WHERE 1=1';
    $params = [];
    if ($search) {
        $searchSql .= " AND (title LIKE ? OR description LIKE ? OR severity LIKE ?)";
        $params[] = '%' . $search . '%';
        $params[] = '%' . $search . '%';
        $params[] = '%' . $search . '%';
    }
    if ($severityFilter) {
        $searchSql .= " AND severity = ?";
        $params[] = $severityFilter;
    }
    if ($statusFilter) {
        $searchSql .= " AND status = ?";
        $params[] = $statusFilter;
    }

    // Get total records for pagination
global $conn;
    $totalQuery = "SELECT COUNT(*) FROM vulnerabilities" . $searchSql;
    $totalStmt = $conn->prepare($totalQuery);

    // Bind params only if there are any
    if (!empty($params)) {
        $totalStmt->bind_param(str_repeat('s', count($params)), ...$params);
    }

    $totalStmt->execute();
    $totalStmt->bind_result($totalRecords);
    $totalStmt->fetch();
    $totalStmt->close();
    $totalPages = ceil($totalRecords / $limit);

    // Fetch vulnerabilities based on search, filters, and pagination
    $vulnQuery = "SELECT * FROM vulnerabilities" . $searchSql . " LIMIT ? OFFSET ?";
    $stmt = $conn->prepare($vulnQuery);

    // Add limit and offset to params
    $params[] = $limit;
    $params[] = $offset;

    // Bind the parameters (including integers for limit and offset)
    if (!empty($params)) {
        $stmt->bind_param(str_repeat('s', count($params) - 2) . 'ii', ...$params);
    }

    $stmt->execute();
    $result = $stmt->get_result();
    $vulnerabilities = $result->fetch_all(MYSQLI_ASSOC);
    $stmt->close();
    $conn->close();
?>

    <!-- Search and Filter Form -->
    <form method="GET" action="">
        <input type="text" name="search" placeholder="Search vulnerabilities" value="<?php echo htmlspecialchars($search); ?>">

        <!-- Filter by Severity -->
        <select name="severity">
            <option value="">All Severities</option>
            <option value="Low" <?php echo $severityFilter === 'Low' ? 'selected' : ''; ?>>Low</option>
            <option value="Medium" <?php echo $severityFilter === 'Medium' ? 'selected' : ''; ?>>Medium</option>
            <option value="High" <?php echo $severityFilter === 'High' ? 'selected' : ''; ?>>High</option>
            <option value="Critical" <?php echo $severityFilter === 'Critical' ? 'selected' : ''; ?>>Critical</option>
        </select>

        <!-- Filter by Status -->
        <select name="status">
            <option value="">All Statuses</option>
            <option value="Open" <?php echo $statusFilter === 'Open' ? 'selected' : ''; ?>>Open</option>
            <option value="Resolved" <?php echo $statusFilter === 'Resolved' ? 'selected' : ''; ?>>Resolved</option>
            <option value="Closed" <?php echo $statusFilter === 'Closed' ? 'selected' : ''; ?>>Closed</option>
        </select>

        <button type="submit" class="btn btn-primary">Search</button>
    </form>

    <!-- Table Display -->
    <table class="table">
        <thead>
            <tr>
                <th>Title</th>
                <th>Description</th>
                <th>Severity</th>
                <th>Reported Date</th>
                <th>Status</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php if ($vulnerabilities): ?>
                <?php foreach ($vulnerabilities as $vulnerability): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($vulnerability['title']); ?></td>
                        <td><?php echo htmlspecialchars($vulnerability['description']); ?></td>
                        <td><?php echo htmlspecialchars($vulnerability['severity']); ?></td>
                        <td><?php echo htmlspecialchars($vulnerability['reported_date']); ?></td>
                        <td><?php echo htmlspecialchars($vulnerability['status']); ?></td>
                        <td>
                            <a href="/e/<?php echo $vulnerability['id']; ?>">Edit</a> |
                            <a href="#" onclick="event.preventDefault(); if (confirm('Are you sure you want to delete this item?')) { fetch('/d/<?php echo $vulnerability['id']; ?>', { method: 'DELETE' }).then(response => { if (response.ok) { window.location.href = '/'; } else { alert('Failed to delete vulnerability'); } }); }">Delete</a>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php else: ?>
                <tr>
                    <td colspan="6">No vulnerabilities found.</td>
                </tr>
            <?php endif; ?>
        </tbody>
    </table>

    <!-- Pagination -->
    <div class="pagination">
        <?php if ($page > 1): ?>
            <a href="<?php echo generateUrl($page - 1); ?>" class="btn btn-secondary">Previous</a>
        <?php endif; ?>

        <?php for ($i = 1; $i <= $totalPages; $i++): ?>
            <a href="<?php echo generateUrl($i); ?>" class="btn btn-secondary <?php echo $i === $page ? 'active' : ''; ?>">
                <?php echo $i; ?>
            </a>
        <?php endfor; ?>

        <?php if ($page < $totalPages): ?>
            <a href="<?php echo generateUrl($page + 1); ?>" class="btn btn-secondary">Next</a>
        <?php endif; ?>
    </div>

    <a href="/if" class="btn btn-primary">Import</a>
    <a href="/c" class="btn btn-primary">Create</a>
    <a href="/e" class="btn btn-primary">Export</a>
<?php
}

function generateUrl($page)
{
    global $search, $severityFilter, $statusFilter;
    return "?page=$page" .
        ($search ? "&search=" . urlencode($search) : '') .
        ($severityFilter ? "&severity=" . urlencode($severityFilter) : '') .
        ($statusFilter ? "&status=" . urlencode($statusFilter) : '');
}

function middleware()
{
    $hashed_password = '';
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_SESSION['original_password'])) {
        if (password_verify($_POST['password'], $hashed_password)) {
            $_SESSION['original_password'] = $_POST['password'];
            header('Location: /');
            exit;
        } else {
            echo 'Invalid password. Please try again.';
        }
    }

    if (!isset($_SESSION['original_password']) || !password_verify($_SESSION['original_password'], $hashed_password)) {
        echo '<form action="/v" method="post">
            <input type="password" name="password" id="password" placeholder="Password">
            <button type="submit">Unlock</button>
          </form>';
        exit;
    }
}
