### **Why I Built This**

`Swan_lib` was created to help Go developers handle JWT authentication, CORS, and common API tasks easily when working with `net/http`. I built this because, while working on my own microservice for a portfolio project, I found myself repeating the same code too often. Instead of getting frustrated, I wrote this library to save time, reduce complexity, and focus on the actual business logic.

I haved tested the JWT middleware and I believe also the CORS will work
---

### Available Methods in `swan_lib`


Here’s a quick rundown of what `swan_lib` offers to simplify your API development with `net/http`:

---

#### **JWT Methods**

- **`NewJWTManager(secretKey string, duration time.Duration)`**  
  Create a manager for generating and verifying JWTs with a secret key and expiration duration.

- **`GenerateToken(userID string, customClaims map[string]any)`**  
  Generate a JWT with a user ID and optional custom claims.

- **`NewJWTMiddleware(secretKey string)`**  
  Set up middleware to validate JWTs on protected routes.

- **`Authorize(next http.Handler)`**  
  Middleware that checks if a valid JWT is present in the request.

---

#### **CORS Methods**

- **`NewCORSMiddleware()`**  
  Create a CORS middleware to handle cross-origin requests.

- **`AllowOrigins(origins []string)`**  
  Specify allowed origins for CORS.

- **`AllowMethods(methods []string)`**  
  Define allowed HTTP methods (GET, POST, etc.) for CORS.

- **`AllowHeaders(headers []string)`**  
  Set which headers are allowed in CORS requests.

- **`AllowCredentials(allowed bool)`**  
  Allow or disallow credentials in cross-origin requests.

- **`Handler(next http.Handler)`**  
  Apply CORS settings to the provided handler.

---

#### **General Utilities**

- **`JSONResponse(w http.ResponseWriter, status int, data any)`**  
  Send a JSON response with the given status and data.

- **`ErrorResponse(w http.ResponseWriter, status int, message string, err error)`**  
  Send a standard error response.

- **`ParseBody(r http.Request, target any)`**  
  Parse the request body into the provided struct.

---

### **Installation**

To get started with `swan_lib`, run the following command:

```bash
go get github.com/SwanHtetAungPhyo/swan_lib
```

---
