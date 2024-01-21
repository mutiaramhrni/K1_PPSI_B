// require("dotenv").config()
const fs = require('fs')
const express = require('express')
const mysql = require('mysql2')
const expressLayouts = require('express-ejs-layouts')
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const path=require("path")
const moment = require('moment')
const multer = require('multer')
const bcrypt = require('bcrypt')
const cookieParser = require('cookie-parser')
const session = require('express-session')
const flash = require('connect-flash')
const slugify = require('slugify')


const app = express()
const port = 3000

// middleware untuk parsing request body
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());


app.set('views', path.join(__dirname, '/views'));

app.use('/css', express.static(path.resolve(__dirname, "assets/css")));
app.use('/img', express.static(path.resolve(__dirname, "assets/img")));
app.use('/submission', express.static('/img'));

// template engine
app.set('view engine', 'ejs')

// layout ejs
app.use(expressLayouts);

// mengatur folder views
app.set('views', './views');
// Middleware session
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));




// Middleware flash messages
app.use(flash());

// Create multer storage configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

// Create multer upload configuration
const upload = multer({ storage: storage });

// Konfigurasi koneksi ke database
const db = mysql.createConnection({
  host: 'localhost', 
  user: 'root',
  password: '',
  database: 'ppsitb' 
});

db.connect((err) => {
  if (err) {
    console.error('Gagal terkoneksi ke database:', err);
  } else {
    console.log('Terhubung ke database MySQL');
  }
});
const saltRounds = 10;

//register dan login
app.get('/register', function (req, res) {
  const errorMessage = req.session.errorMessage;
  req.session.errorMessage = ''; // Clear the error message from session
  const successMessage = req.session.successMessage;
  req.session.successMessage = '';
  res.render('register',{
    title:'Register',
    layout:'layouts/auth-layout',
    errorMessage : errorMessage,
    successMessage : successMessage
  });
})

app.post('/register', function (req, res) {
  const { username, id_user, password, confirm_password, role } = req.body;

  // cek apakah user yang regist sudah mendaftar
  const sqlCheck = 'SELECT * FROM user WHERE id_user = ?';
  db.query(sqlCheck, [id_user], (err, result) => {
    if (err) throw err;   

    if (result.length > 0) {
      console.error({ message: 'id_user sudah terdaftar', err });
      req.session.errorMessage = 'id_user sudah terdaftar';
      return res.redirect('/tambah-user');
    }
 
    if (password !== confirm_password) {
      console.error({ message: 'Password tidak cocok!', err });
      req.session.errorMessage = 'Password tidak cocok!';
      return res.redirect('/tambah-user');
    }

    // Hash password
    bcrypt.hash(password, saltRounds, function(err, hash) {
      if (err) throw err; 

      const sqlInsert = "INSERT INTO user (username, id_user, password, role) VALUES (?, ?, ?, ?)";
      const values = [username, id_user, hash, role];
      db.query(sqlInsert, values, (err, result) => {
        if (err) throw err; 
        console.log({ message: 'Registrasi berhasil', values });
        res.redirect('/dashboard');
      });
    });
  });
});




// login page
app.get('/login', function (req, res) {
  const errorMessage = req.session.errorMessage;
  req.session.errorMessage = ''; // Clear the error message from session
  const successMessage = req.session.successMessage;
  req.session.successMessage = '';
  res.render('login',{
    title:'Login',
    layout:'layouts/auth-layout',
    errorMessage : errorMessage,
    successMessage : successMessage
  });
})

app.post('/login', function (req, res) {
  const { id_user, password } = req.body;

  const sql = `SELECT * FROM user WHERE id_user = ?`;

  db.query(sql, [id_user], function(err, result) {
    if (err) {
      console.error({ message: 'Internal Server Error', err });
      req.session.errorMessage = 'Internal Server Error';
      return res.redirect('/login');
    }
    if (result.length === 0) {
      console.error({ message: 'id_user atau Password salah!!', err });
      req.session.errorMessage = 'id_user atau Password salah!!';
      return res.redirect('/login');
    }

    const user = result[0];
 
    // compare password
    bcrypt.compare(password, user.password, function(err, isValid) {
      if (err) {
        console.error({ message: 'Internal Server Error', err });
        req.session.errorMessage = 'Internal Server Error';
        return res.redirect('/login');
      }

      if (!isValid) {
        console.error({ message: 'id_user atau Password salah!!', err });
        req.session.errorMessage = 'id_user atau Password salah!!';
        return res.redirect('/login');
      }

      // generate token
      const token = jwt.sign({ id_user: user.id_user }, 'secret_key');
      res.cookie('token', token, { httpOnly: true });

      console.log({ message: 'Login Berhasil', user });
      return res.redirect('/');
    });
  });
});



// logout
app.get('/logout', function(req, res) {
  res.clearCookie('token');
  res.redirect('/login');
});

// middleware untuk memeriksa apakah user sudah login atau belum
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    res.redirect('/login');
    return;
  }
  

  jwt.verify(token, 'secret_key', function(err, decoded) {
    if (err) {
      res.redirect('/login');
      return;
    }

    req.id_user = decoded.id_user;
    next();
  });
}

app.use(requireAuth, (req, res, next) => {
  
  const query1 = `SELECT * FROM user WHERE id_user = ${req.id_user}`;
  db.query(query1, function (error, results1) {
    if (error) throw error;

    const user = results1[0];
    res.locals.user = user; 
    next();
  });
}); 

// index page
app.get('/', requireAuth, function (req, res) {
  const dsnSql = `SELECT * FROM user WHERE id_user = ${req.id_user}`;
  db.query(dsnSql, (err, result)=>{
    if (err) throw err;
    res.render('index', {
      user:result[0], 
      title: 'Home',
      layout: 'layouts/main-layout'
    }) 
  })
})

app.get('/edit-user-dashboard/:id_user', function (req, res) {
  const id_user = req.params.id_user;
  const dsnSql = `SELECT * FROM user WHERE id_user = ${id_user}`;
  db.query(dsnSql, (err, result)=>{
    if (err) throw err;
    res.render('edit-user-dashboard', {
      user:result[0], 
      title: 'Edit User',
      layout: 'layouts/main-layout'
    }) 
  })
})

app.get('/edit-kelas-dashboard/:id_kelas', function (req, res) {
  const id_kelas = req.params.id_kelas;
  const dsnSql = `SELECT * FROM kelas WHERE id_kelas = ${id_kelas}`;
  db.query(dsnSql, (err, result)=>{
    if (err) throw err;
    res.render('edit-kelas-dashboard', {
      kelas:result[0], 
      title: 'Edit kelas',
      layout: 'layouts/main-layout'
    }) 
  })
})

app.post('/edit-user-dashboard', (req, res) => {
  const { username, email, role, id_user } = req.body;

  // Build the SQL query for updating 'username' and 'email'
  const updateQuery = 'UPDATE user SET username=?, email=?, role=? WHERE id_user=?';

  // Execute the query
  db.query(updateQuery, [username, email, role, id_user], (err, result) => {
    if (err) {
      console.error(err);
      res.redirect('/dashboard');
      return;
    }

    console.log('User profile updated in MySQL!');
    res.redirect('/dashboard');
  });
});

app.post('/edit-kelas-dashboard', (req, res) => {
  const { title, enroll_key, excerpt, id_kelas} = req.body;

  // Build the SQL query for updating 'title' and 'enroll_key'
  const updateQuery = 'UPDATE kelas SET title=?, enroll_key=?, excerpt=? WHERE id_kelas=?';

  // Execute the query
  db.query(updateQuery, [title, enroll_key, excerpt, id_kelas], (err, result) => {
    if (err) {
      console.error(err);
      res.redirect('/kelola-kelas');
      return;
    }

    console.log('kelas updated in MySQL!');
    res.redirect('/kelola-kelas');
  });
});


// dashboard page
app.get('/dashboard', requireAuth, function (req, res) {
  const itemsPerPage = 20;
  const currentPage = parseInt(req.query.page) || 1;

  const queryCount = 'SELECT COUNT(*) AS totalItems FROM user';
  
  const offset = (currentPage - 1) * itemsPerPage;
  const queryData = `
    SELECT user.username, user.id_user, user.role, user.email
    FROM user
    WHERE user.role != 'admin'
    LIMIT ${itemsPerPage} OFFSET ${offset}
  `;

  db.query(queryCount, (errCount, resultCount) => {
    if (errCount) {
      console.error("Error counting total items:", errCount);
      return res.status(500).send("Internal Server Error");
    }

    const totalItems = resultCount[0].totalItems;
    const totalPages = Math.ceil(totalItems / itemsPerPage);
    if (currentPage < 1 || currentPage > totalPages) {
      return res.redirect('/dashboard');
    }

    db.query(queryData, (errData, resultData) => {
      if (errData) {
        console.error("Error fetching data:", errData);
        return res.status(500).send("Internal Server Error");
      }

      res.render('dashboard', {
        items: resultData,
        currentPage: currentPage,
        totalPages: totalPages,
        layout: 'layouts/main-layout',
        title: 'Kelola User',
        moment: moment
      });
    });
  });
});

// kelola kelas page
app.get('/kelola-kelas', requireAuth, function (req, res) {
  const itemsPerPage = 20;
  const currentPage = parseInt(req.query.page) || 1;

  const queryCount = 'SELECT COUNT(*) AS totalItems FROM kelas';
  
  const offset = (currentPage - 1) * itemsPerPage;
  const queryData = `
  SELECT kelas.*, user.username, user.id_user FROM kelas 
  JOIN user ON kelas.id_user = user.id_user
  LIMIT ${itemsPerPage} OFFSET ${offset}
  `;

  db.query(queryCount, (errCount, resultCount) => {
    if (errCount) {
      console.error("Error counting total items:", errCount);
      return res.status(500).send("Internal Server Error");
    }

    const totalItems = resultCount[0].totalItems;
    const totalPages = Math.ceil(totalItems / itemsPerPage);
    if (currentPage < 1 || currentPage > totalPages) {
      return res.redirect('/kelola-kelas');
    }

    db.query(queryData, (errData, resultData) => {
      if (errData) {
        console.error("Error fetching data:", errData);
        return res.status(500).send("Internal Server Error");
      }

      res.render('kelola-kelas', {
        items: resultData,
        currentPage: currentPage,
        totalPages: totalPages,
        layout: 'layouts/main-layout',
        title: 'Kelola Kelas',
        moment: moment
      });
    });
  }); 
});

// kelola projek page
app.get('/kelola-projek', requireAuth, function (req, res) {
  const itemsPerPage = 20;
  const currentPage = parseInt(req.query.page) || 1;

  const queryCount = 'SELECT COUNT(*) AS totalItems FROM submission';
  
  const offset = (currentPage - 1) * itemsPerPage;
  const queryData = `
  SELECT submission.*, user.username, user.id_user FROM submission 
  JOIN user ON submission.id_user = user.id_user
  LIMIT ${itemsPerPage} OFFSET ${offset}
  `;

  db.query(queryCount, (errCount, resultCount) => {
    if (errCount) {
      console.error("Error counting total items:", errCount);
      return res.status(500).send("Internal Server Error");
    }

    const totalItems = resultCount[0].totalItems;
    const totalPages = Math.ceil(totalItems / itemsPerPage);
    if (currentPage < 1 || currentPage > totalPages) {
      return res.redirect('/kelola-projek');
    }

    db.query(queryData, (errData, resultData) => {
      if (errData) {
        console.error("Error fetching data:", errData);
        return res.status(500).send("Internal Server Error");
      }

      res.render('kelola-projek', {
        items: resultData,
        currentPage: currentPage,
        totalPages: totalPages,
        layout: 'layouts/main-layout',
        title: 'Kelola projek',
        moment: moment
      });
    });
  }); 
});

app.get('/delete-user-dashboard/:id_user', (req, res) => {
  const id_user = req.params.id_user;

  // First, delete related records from the 'enroll' table
  const deleteEnrollSql = `DELETE FROM enroll WHERE id_user = ${id_user}`;

  db.query(deleteEnrollSql, (errEnroll, resultEnroll) => {
    if (errEnroll) {
      console.error("Error deleting enroll records:", errEnroll);
      return res.status(500).send("Internal Server Error");
    }

    // Once enroll records are deleted, delete the user from the 'user' table
    const deleteUserSql = `DELETE FROM user WHERE id_user = ${id_user}`;

    db.query(deleteUserSql, (errUser, resultUser) => {
      if (errUser) {
        console.error("Error deleting user:", errUser);
        return res.status(500).send("Internal Server Error");
      }

      console.log({ resultUser });
      res.redirect('/dashboard');
    });
  });
});

app.get('/delete-kelas-dashboard/:id_kelas', (req, res) => {
  const id_kelas = req.params.id_kelas;

    const deletekelasSql = `DELETE FROM kelas WHERE id_kelas = ${id_kelas}`;

    db.query(deletekelasSql, (errKelas, resultKelas) => {
      if (errKelas) {
        console.error("Error deleting kelas:", errKelas);
        return res.status(500).send("Internal Server Error");
      }
      console.log({ resultKelas });
      res.redirect('/kelola-kelas');
  });
});


app.get('/delete-projek-dashboard/:id_upload', (req, res) => {
  const id_upload = req.params.id_upload;

    const deleteprojekSql = `DELETE FROM submission WHERE id_upload = ${id_upload}`;

    db.query(deleteprojekSql, (errprojek, resultprojek) => {
      if (errprojek) {
        console.error("Error deleting projek:", errprojek);
        return res.status(500).send("Internal Server Error");
      }
      console.log({ resultprojek });
      res.redirect('/kelola-projek');
  });
});






app.get('/search-in-table', (req, res) => {
  const itemsPerPage = 10;
  const currentPage = parseInt(req.query.page) || 1;
  const searchQuery = req.query.search || '';

  const queryCount = 'SELECT COUNT(*) AS totalItems FROM user';
  const queryData = `
  SELECT user.*
  FROM user
  WHERE (user.id_user LIKE '%${searchQuery}%'
    OR user.username LIKE '%${searchQuery}%'
    OR user.email LIKE '%${searchQuery}%')
    AND user.role != 'admin'
  LIMIT ${itemsPerPage} OFFSET ${(currentPage - 1) * itemsPerPage}
  `;

  db.query(queryCount, (errCount, resultCount) => {
      if (errCount) throw errCount;

      const totalItems = resultCount[0].totalItems;
      const totalPages = Math.ceil(totalItems / itemsPerPage);

      if (currentPage < 1 || currentPage > totalPages) {
          res.redirect('/dashboard');
          return;
      }

      db.query(queryData, (errData, resultData) => {
          if (errData) throw errData;

          res.render('dashboard', {
              items: resultData,
              currentPage: currentPage,
              totalPages: totalPages,
              layout: 'layouts/main-layout',
              title: 'Kelola User',
              moment: moment
          });
      });
  });
});

app.get('/search-in-table-kelas', (req, res) => {
  const itemsPerPage = 10;
  const currentPage = parseInt(req.query.page) || 1;
  const searchQuery = req.query.search || '';

  const queryCount = 'SELECT COUNT(*) AS totalItems FROM kelas';
  const queryData = `
  SELECT kelas.*, user.username 
  FROM kelas
  JOIN user ON kelas.id_user = user.id_user
  WHERE (kelas.title LIKE '%${searchQuery}%'
     OR kelas.created_at LIKE '%${searchQuery}%'
     OR user.username LIKE '%${searchQuery}%'
     OR user.id_user LIKE '%${searchQuery}%'
     OR kelas.excerpt LIKE '%${searchQuery}%'
     OR kelas.enroll_key LIKE '%${searchQuery}%')
  LIMIT ${itemsPerPage} OFFSET ${(currentPage - 1) * itemsPerPage}
  
  `;

  db.query(queryCount, (errCount, resultCount) => {
      if (errCount) throw errCount;

      const totalItems = resultCount[0].totalItems;
      const totalPages = Math.ceil(totalItems / itemsPerPage);

      if (currentPage < 1 || currentPage > totalPages) {
          res.redirect('/kelola-kelas');
          return;
      }

      db.query(queryData, (errData, resultData) => {
          if (errData) throw errData;

          res.render('kelola-kelas', {
              items: resultData,
              currentPage: currentPage,
              totalPages: totalPages,
              layout: 'layouts/main-layout',
              title: 'Kelola kelas',
              moment: moment
          });
      });
  });
});

app.get('/search-in-table-projek', (req, res) => {
  const itemsPerPage = 10;
  const currentPage = parseInt(req.query.page) || 1;
  const searchQuery = req.query.search || '';

  const queryCount = 'SELECT COUNT(*) AS totalItems FROM submission';
  const queryData = `
  SELECT submission.*, user.username 
  FROM submission
  JOIN user ON submission.id_user = user.id_user
  WHERE (submission.file LIKE '%${searchQuery}%'
     OR submission.created_at LIKE '%${searchQuery}%'
     OR user.id_user LIKE '%${searchQuery}%'
     OR user.username LIKE '%${searchQuery}%')
  LIMIT ${itemsPerPage} OFFSET ${(currentPage - 1) * itemsPerPage}
  `;

  db.query(queryCount, (errCount, resultCount) => {
      if (errCount) throw errCount;

      const totalItems = resultCount[0].totalItems;
      const totalPages = Math.ceil(totalItems / itemsPerPage);

      if (currentPage < 1 || currentPage > totalPages) {
          res.redirect('/kelola-projek');
          return;
      }

      db.query(queryData, (errData, resultData) => {
          if (errData) throw errData;

          res.render('kelola-projek', {
              items: resultData,
              currentPage: currentPage,
              totalPages: totalPages,
              layout: 'layouts/main-layout',
              title: 'Kelola projek',
              moment: moment
          });
      });
  });
});


  app.get('/delete-user-dashboard/:id_user', (req,res)=>{
    let id_user = req.params.id_user;
    const deleteSql = `DELETE FROM user WHERE id_user = ${id_user}`
    db.query(deleteSql, (err, result)=>{
      if (err) throw err;
      console.log({result})
      res.redirect('/dashboard')
    })
  })


app.get('/menu', function (req, res) {
  res.render('menu', {
    title: 'Menu',
    layout: 'layouts/main-layout'
  });
});

app.get('/upload/:id_kelas', function (req, res) {
  const id_kelas = req.params.id_kelas;
  const kelasSql = `SELECT * FROM kelas 
  WHERE id_kelas = ?`
  db.query(kelasSql,id_kelas, (err, result)=>{
    if (err) throw err;
    res.render('upload', {
      kelas : result[0],
      title: 'Upload',
      layout: 'layouts/main-layout'
    })
  })
});


app.post('/upload-file', upload.single('file'), requireAuth, (req, res) => {
  let id_user = req.id_user;
  const file = req.file;
  const id_kelas = req.body.id_kelas;


  // Pastikan file yang diupload memiliki ekstensi zip atau rar
  const allowedExtensions = ['.zip', '.rar'];
  const fileExtension = path.extname(file.originalname).toLowerCase();

  if (!allowedExtensions.includes(fileExtension)) {
    const errorMessage = 'File harus berupa format zip atau rar.';
    // Menampilkan notifikasi alert pada sisi klien
    return res.render('error',{
       message: errorMessage,
       layout : 'layouts/main-layout',
       title: 'Error'
      }
     );
  }

  const insertSql = `INSERT INTO submission (id_kelas, id_user, file) VALUES (?, ?, ?)`; 
  const insertValues = [id_kelas, id_user, file.filename];
  
  db.query(insertSql, insertValues, (err, result) => {
    if (err) {
      throw err;
    }
    console.log({ message: 'Submission complete!', insertValues });
    res.redirect(`/kelas`);
  });
});

app.get('/about-us', requireAuth,function (req, res) {
  res.render('about-us', {
    title: 'About Us',
    layout: 'layouts/layout-berita'
});
});

app.get('/delete-file/:id_upload', (req, res) => {
  const id_upload = req.params.id_upload;

  // Hapus dari tabel anak terlebih dahulu
  const deleteGradesSql = `DELETE FROM grades WHERE id_upload = ?;`;
  db.query(deleteGradesSql, [id_upload], (err, result) => {
    if (err) {
      throw err;
    }

    // Hapus dari tabel utama
    const deleteSubmissionSql = `DELETE FROM submission WHERE id_upload = ?;`;
    db.query(deleteSubmissionSql, [id_upload], (err, result) => {
      if (err) {
        throw err;
      }

      console.log('file berhasil dihapus', { result });
      res.redirect('/kelas');
    });
  });
});

app.get('/delete-file-user/:id_upload', (req, res) => {
  const id_upload = req.params.id_upload;

  // Hapus dari tabel anak terlebih dahulu
  const deleteGradesSql = `DELETE FROM grades WHERE id_upload = ?;`;
  db.query(deleteGradesSql, [id_upload], (err, result) => {
    if (err) {
      throw err;
    }

    // Hapus dari tabel utama
    const deleteSubmissionSql = `DELETE FROM submission WHERE id_upload = ?;`;
    db.query(deleteSubmissionSql, [id_upload], (err, result) => {
      if (err) {
        throw err;
      }

      console.log('file berhasil dihapus', { result });
      res.redirect('/kelola-projek');
    });
  });
});



app.get('/pencarian', function (req, res) {
  res.render('pencarian', {
    title: 'pencarian',
    layout: 'layouts/main-layout'
  });
});

app.get('/beri-nilai/:id_upload/:id_user', function (req, res) {
  const id_upload = req.params.id_upload;
  const id_user = req.params.id_user;
  const gradesSql = `SELECT * FROM grades WHERE id_upload = '${id_upload}' AND id_user = '${id_user}'
   `; 
  db.query(gradesSql,  (err,results)=>{
    if (err) throw err; 
  
  res.render('beri-nilai', {
    grades:results[0],  
    id_upload:id_upload,  
    id_user:id_user,
    title: 'Penilaian',
    layout: 'layouts/main-layout'
    })
  });
});


app.post('/beri-nilai', requireAuth, (req, res) => {
  const { id_user, id_upload, grade, feedback } = req.body;

  const selectQuery = 'SELECT * FROM grades WHERE id_user = ? AND id_upload = ?';
  db.query(selectQuery, [id_user, id_upload], (selectErr, selectResults) => {
    if (selectErr) {
      console.error(selectErr);
      return;
    }

    // Check if a record exists for the user and upload ID
    if (selectResults.length === 0) {
      // If no record exists, insert a new record with the user and upload ID
      const insertQuery = 'INSERT INTO grades (id_user, id_upload) VALUES (?, ?)';
      db.query(insertQuery, [id_user, id_upload], (insertErr, insertResults) => {
        if (insertErr) {
          console.error(insertErr);
          return;
        }
        console.log('New record inserted with id_user and id_upload');
        // Proceed to update the grade and feedback
        updateGradeAndFeedback();
      });
    } else {
      // If a record already exists, directly update the grade and feedback
      updateGradeAndFeedback();
    }

    function updateGradeAndFeedback() {
      // Build the SQL query dynamically for updating grade and feedback
      let updateQuery = 'UPDATE grades SET';
      const values = [];

      if (grade) {
        updateQuery += ' grade=?';
        values.push(grade);
      }

      if (feedback) {
        if (grade) {
          updateQuery += ',';
        }
        updateQuery += ' feedback=?';
        values.push(feedback);
      }

      updateQuery += ' WHERE id_user=? AND id_upload=?';
      values.push(id_user, id_upload);

      // Perform the update for grade and feedback
      db.query(updateQuery, values, (updateErr, updateResults) => {
        if (updateErr) {
          console.error(updateErr);
          return;
        }
        console.log('Grade and feedback updated');
        res.redirect('/kelas');
      });
    }
  });
});





app.get('/kelas',requireAuth, function (req, res) {
  const id_user = req.id_user;
  const kelasSql = `SELECT kelas.*
  FROM kelas
  INNER JOIN enroll ON kelas.enroll_key = enroll.enroll_key
  INNER JOIN user ON kelas.id_user = user.id_user
  WHERE enroll.id_user = ${id_user}`;

  const kelasDsnSql = `SELECT kelas.*,  user.*
  FROM kelas
  JOIN user ON user.id_user = kelas.id_user
  WHERE user.id_user = ${id_user}`;

  db.query(kelasSql, (err,kelasResult)=>{
    if (err) throw err;
  db.query(kelasDsnSql, (err,kelasDsnResult)=>{
    if (err) throw err;
    res.render('kelas', {
      kelas : kelasResult,
      kelasDsn : kelasDsnResult,
      title: 'Kelas',
      moment:moment,
      layout: 'layouts/main-layout'
     })
    })
  })
})

app.get('/aboutus', function (req, res) {
  res.render('aboutus', {
    title: 'About Us',
    layout: 'layouts/main-layout'
  });
});

app.get('/detailKelas/:id_kelas', requireAuth, function (req, res) {
  const id_kelas = req.params.id_kelas;
  let id_user = req.id_user;
  const fileSql = `SELECT submission.*, user.* FROM submission 
  JOIN user ON user.id_user = submission.id_user
  WHERE submission.id_user = ${id_user} AND submission.id_kelas = ${id_kelas}`;
  const fileToDsn = `SELECT submission.*, user.* FROM submission 
  JOIN user ON user.id_user = submission.id_user
  WHERE submission.id_user = user.id_user AND submission.id_kelas = ${id_kelas}`;
  const kelasSql = `SELECT * FROM kelas 
  WHERE kelas.id_kelas = ?`; 

  db.query(fileSql, (err, filesResult) => { 
    if (err) throw err; 
 
    db.query(fileToDsn, (err, fileToDsn) => {
      if (err) throw err;

    db.query(kelasSql, id_kelas, (err, kelas) => {
      if (err) throw err;

      const detailFile = filesResult[0];
      let fileSizeInKilobytes = null;

      if (detailFile) {
        const fs = require('fs');
        const filePath = 'uploads/' + detailFile.file;
        if (fs.existsSync(filePath)) {
          const stats = fs.statSync(filePath);
          fileSizeInBytes = stats.size;
          fileSizeInKilobytes = (fileSizeInBytes / 1024).toFixed(2) + ' KB';
        }
      }

      res.render('detailKelas', {
        files: filesResult,
        filesToDsn: fileToDsn,
        kelas: kelas[0],
        moment: moment,
        fileSizeInKilobytes: fileSizeInKilobytes,
        title: 'Detail kelas',
        layout: 'layouts/main-layout'
        });
      });
    }); 
  });
});


app.get('/buat-kelas', function (req, res) {
    res.render('buat-kelas', {
      title: 'Buat Kelas', 
      layout: 'layouts/main-layout'
  })
}) 

app.get('/tambah-kelas', function (req, res) {
    res.render('tambah-kelas', {
      title: 'Tambah Kelas', 
      layout: 'layouts/main-layout'
  })
}) 

app.post('/buat-kelas', requireAuth, (req, res) => {
  let id_user = req.id_user;
  const { title, enroll_key, excerpt } = req.body;

  // Menghasilkan slug dari judul
  const slug_kelas = slugify(title, {
    replacement: '-',
    lower: true,
  });

  // Insert data ke tabel 'kelas'  
  const insertKelasSql = `INSERT INTO kelas (id_user, slug_kelas, title, enroll_key, excerpt) VALUES (?, ?, ?, ?, ?)`;
  const insertKelasValues = [id_user, slug_kelas, title, enroll_key, excerpt];
  db.query(insertKelasSql, insertKelasValues, (err, kelasResult) => {
    if (err) {
      throw err;
    }
      console.log({ message: 'Create complete!', insertKelasValues });
      res.redirect('/kelas');
  });
});

app.post('/tambah-kelas', requireAuth, (req, res) => {
  let id_user = req.id_user;
  const { title, enroll_key, excerpt } = req.body;

  // Menghasilkan slug dari judul
  const slug_kelas = slugify(title, {
    replacement: '-',
    lower: true,
  });

  // Insert data ke tabel 'kelas'  
  const insertKelasSql = `INSERT INTO kelas (id_user, slug_kelas, title, enroll_key, excerpt) VALUES (?, ?, ?, ?, ?)`;
  const insertKelasValues = [id_user, slug_kelas, title, enroll_key, excerpt];
  db.query(insertKelasSql, insertKelasValues, (err, kelasResult) => {
    if (err) {
      throw err;
    }
      console.log({ message: 'Create complete!', insertKelasValues });
      res.redirect('/kelola-kelas');
  });
});






app.get('/propil', requireAuth, function (req, res) {
  let id_user = req.id_user;
  const userSql = `SELECT * FROM user WHERE id_user = ${id_user}`;
  db.query(userSql, (err, Result)=>{
    if (err) throw err;
    res.render('propil', {
      user : Result[0],
      title: 'Profil',
      layout: 'layouts/main-layout'
    })
  })
}) 

app.get('/change-password', function (req, res) {
    res.render('change-password', {
      title: 'change password',
      layout: 'layouts/main-layout'
  })
}) 

app.get('/tambah-user', function (req, res) {
    res.render('tambah-user', {
      title: 'tambah user',
      layout: 'layouts/main-layout'
  })
}) 



app.post('/edit-propil', upload.single('avatar'), requireAuth, (req, res) => {
  const id_user = req.id_user;
  const { username, email } = req.body;
  let avatar = null;

  if (req.file) {
    // Avatar file was uploaded
    avatar = req.file.filename;

    const avatarAllowedExtensions = ['.jpg', '.jpeg', '.png'];
    const avatarExtension = path.extname(req.file.originalname).toLowerCase();

    if (!avatarAllowedExtensions.includes(avatarExtension)) {
      // Delete the invalid file
      fs.unlinkSync(req.file.path);
      res.redirect('/propil');
      return;
    }

    // Move the uploaded file to the destination directory
    const avatarSource = path.join(__dirname, 'uploads', avatar);
    const avatarDestination = path.join(__dirname, 'assets', 'img', avatar);
    fs.renameSync(avatarSource, avatarDestination);
  }

  // Build the SQL query dynamically based on whether 'avatar' is provided
  let updateQuery = 'UPDATE user SET username=?, email=?';
  const values = [username, email];

  if (avatar) {
    updateQuery += ', avatar=?';
    values.push(avatar);
  }

  updateQuery += ' WHERE id_user=?';
  values.push(id_user);

  // Update data in MySQL
  db.query(updateQuery, values, (err, result) => {
    if (err) {
      console.error(err);
      res.redirect('/propil');
      return;
    }
    console.log('Data updated in MySQL!');
    res.redirect('/propil');
  });
});

app.post('/change-password', requireAuth, (req, res) => {
  const { password, newPassword } = req.body;
  const id_user = req.id_user;

  // Check if current password matches with database
  const sql = 'SELECT password FROM user WHERE id_user = ?';
  db.query(sql, [id_user], (err, result) => {
    if (err) {
      console.log({ message: 'Internal Server Error', err });
      
    }

    const hashedPassword = result[0].password;
    bcrypt.compare(password, hashedPassword, (error, isMatch) => {
      if (error) {
        console.log({ message: 'Internal Server Error', err });
      }

      if (isMatch) {
        // If current password matches, hash new password and update database
        bcrypt.hash(newPassword, saltRounds, (err, hashedNewPassword) => {
          if (err) {
            console.log({ message: 'Internal Server Error', err });
          }

          const updateSql = 'UPDATE user SET password = ? WHERE id_user = ?';
          const values = [hashedNewPassword, id_user];
          db.query(updateSql, values , (err, result) => {
            if (err) {
              console.log({ message: 'Internal Server Error', err });
            }
            console.log({ message: 'Password berhasil diubah', values });
            res.redirect('/propil');
          });
        });
      } else {
        // If current password doesn't match, send error message
        console.log({ message: 'Invalid current password', err });
        res.redirect('/propil');
      }
    });
  });
});




app.post('/enroll', requireAuth, function (req, res) {
  const enroll_key = req.body.enroll_key;
  const id_user = req.id_user;

  const selectSql = 'SELECT * FROM kelas WHERE enroll_key = ?';
  db.query(selectSql, [enroll_key], (err, kelasResult) => {
    if (err) {
      console.log({ message: 'Internal server erorr', err });
    }

    if (kelasResult.length > 0) {
      const id_userKelas = kelasResult[0].id_user;

      if (id_userKelas === id_user) {
        console.log({ message: 'Anda tidak bisa enroll form sendiri' });
        res.redirect('/kelas');
      } else {
        const enrollmentsSql = 'SELECT * FROM enroll WHERE id_user = ? AND enroll_key = ?';
        db.query(enrollmentsSql, [id_user, enroll_key], (enrollmentsErr, enrollmentsResult) => {
          if (enrollmentsErr) {
            console.log({ message: 'Internal server erorr', enrollmentsErr });
          }

          if (enrollmentsResult.length > 0) {
            console.log({ message: 'Anda sudah enroll pada form ini!' });
            res.redirect('/kelas');
          } else {
            const insertSql = 'INSERT INTO enroll (id_user, enroll_key) VALUES (?, ?)';
            const values = [id_user, enroll_key];
            db.query(insertSql, values, (insertErr, insertResult) => {
              if (insertErr) {
                throw insertErr;
              }

              console.log({ message: 'Enrollment berhasil' });
              res.redirect('/kelas');
            });
          }
        });
      }
    } else {
      console.log('Invalid enroll key');
    }
  });
});


app.get('/download/:id_user/:id_upload', requireAuth, (req, res) => {
  const id_user = req.params.id_user;
  const id_upload = req.params.id_upload;

  const fileSql = 'SELECT * FROM submission WHERE id_upload = ?';
  db.query(fileSql, [id_upload], function(err, fileResult) {
    if (err) throw err;
    if (fileResult.length === 0) {
      res.status(404).send('file not found');
      return;
    }

    const fileSql = 'SELECT * FROM submission WHERE id_user = ? AND id_upload = ?';
    db.query(fileSql, [id_user, id_upload], function(err, fileResult) {
      if (err) throw err;
      if (fileResult.length === 0) {
        res.status(404).send('file not found');
        return;
      }

      const file = fileResult[0];
      const filePath = `uploads/${file.file}`;

      res.download(filePath, file.file_name, function(err) {
        if (err) {
          console.log(err);
          res.status(500).send('Internal server error');
        }
      });
    });
  });
});


app.get('/search', requireAuth, (req, res) => {
  const query = req.query.query; 

  const contentSql = `
  SELECT submission.*, user.* FROM submission
  JOIN user ON user.id_user = submission.id_user
  WHERE file LIKE ?
  `;


  const searchQuery = `%${query}%`; 

    db.query(contentSql, searchQuery, (err, searchResults) => {
      if (err) {
        throw err;
      }
      const detailFile = searchResults[0];
      let fileSizeInKilobytes = null;

      if (detailFile) {
        const fs = require('fs');
        const filePath = 'uploads/' + detailFile.file;
        if (fs.existsSync(filePath)) {
          const stats = fs.statSync(filePath);
          fileSizeInBytes = stats.size;
          fileSizeInKilobytes = (fileSizeInBytes / 1024).toFixed(2) + ' KB';
        }
      } 

      res.render('search-result', { 
        title: 'Search Results',
        layout: 'layouts/main-layout',
        results: searchResults,
        fileSizeInKilobytes : fileSizeInKilobytes,
        moment: moment,
        query: query
    });
  });
});


app.listen(port,()=>{
  console.log(`listening on port ${port}`)
})
