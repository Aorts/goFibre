package main

import (
	"fmt"
	"strconv"

	"github.com/dgrijalva/jwt-go/v4"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	jwtware "github.com/gofiber/jwt/v3"
)

var db *sqlx.DB

const jwtSecret = "ts"

func main() {
	var err error
	connStr := "postgres://ts:ts@localhost:5432/postgres?sslmode=disable"
	db, err = sqlx.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	err = db.Ping()
	if err != nil {
		panic(err)
	} else {
		fmt.Println("Connected!!")
	}

	app := fiber.New()

	app.Use("/hello", jwtware.New(jwtware.Config{
		SigningMethod: "HS256",
		SigningKey:    []byte(jwtSecret),
		SuccessHandler: func(c *fiber.Ctx) error {
			return c.Next()
		},
		ErrorHandler: func(c *fiber.Ctx, e error) error {
			return fiber.ErrUnauthorized
		},
	}))

	app.Post("/singup", Signup)
	app.Post("/login", Login)
	app.Get("/hello", HelloWorld)
	app.Listen(":8080")
}

func Signup(c *fiber.Ctx) error {

	request := singupReq{}
	err := c.BodyParser(&request)
	if err != nil {
		return err
	}

	if request.Username == "" || request.Password == "" {
		return fiber.ErrUnprocessableEntity
	}

	//queryStr := "insert into users (username, password) values ($1, $2) RETURNING id"
	queryStr := "insert into users (username, password) values ($1, $2) RETURNING id"
	password, err := bcrypt.GenerateFromPassword([]byte(request.Password), 10)
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}
	fmt.Println(password)
	lastInsertId := 0
	err = db.QueryRow(queryStr, request.Username, string(password)).Scan(&lastInsertId)
	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}

	if err != nil {
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}
	user := user{
		Id:       int(lastInsertId),
		Username: request.Username,
		Password: request.Password,
	}

	return c.Status(fiber.StatusCreated).JSON(user)
}

func Login(c *fiber.Ctx) error {
	request := loginReq{}
	err := c.BodyParser(&request)
	if err != nil {
		return err
	}
	if request.Username == "" || request.Password == "" {
		return fiber.ErrUnprocessableEntity
	}

	user := user{}
	query := "select id, username, password from users where username=$1"
	fmt.Println(request.Username)
	err = db.Get(&user, query, request.Username)

	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Incorrect username or password")
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "Incorrect password")
	}

	cliams := jwt.StandardClaims{
		Issuer: strconv.Itoa(user.Id),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, cliams)
	token, err := jwtToken.SignedString([]byte(jwtSecret))
	if err != nil {
		return fiber.ErrInternalServerError
	}

	return c.JSON(fiber.Map{
		"jwtToken": token,
	})
}

func HelloWorld(c *fiber.Ctx) error {
	return c.SendString("Hello World")
}

type user struct {
	Id       int    `db:"id" json:"id"`
	Username string `db:"username" json:"username"`
	Password string `db:"password" json:"password"`
}

type singupReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

//---------------------------------------

func Fiber() {
	app := fiber.New(fiber.Config{
		Prefork: true,
	})

	//Middleware
	app.Use("/hello", func(c *fiber.Ctx) error {
		fmt.Println("before")
		err := c.Next()
		fmt.Println("after")
		return err
	})

	app.Use(requestid.New())
	app.Use(cors.New())

	//Mount
	userApp := fiber.New()
	userApp.Get("/login", func(c *fiber.Ctx) error {
		return c.SendString("hello world")
	})

	app.Mount("/user", userApp)

	app.Server().MaxConnsPerIP = 1

	app.Get("/env", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"BaseURL":     c.BaseURL(),
			"Hostname":    c.Hostname(),
			"IP":          c.IP(),
			"IPs":         c.IPs(),
			"OriginalURL": c.OriginalURL(),
			"Path":        c.Path(),
			"Protocol":    c.Protocol(),
			"Subdomains":  c.Subdomains(),
		})
	})

	app.Post("/body", func(c *fiber.Ctx) error {
		fmt.Printf("IsJson: %v\n", c.Is("json"))
		// fmt.Println(string(c.Body()))

		data := map[string]interface{}{}
		err := c.BodyParser(&data)
		if err != nil {
			return err
		}

		fmt.Println(data)
		return nil
	})

	app.Post("/body2", func(c *fiber.Ctx) error {
		fmt.Printf("IsJson: %v\n", c.Is("json"))
		// fmt.Println(string(c.Body()))

		person := Person{}
		err := c.BodyParser(&person)
		if err != nil {
			return err
		}

		fmt.Println(person)
		return nil
	})

	app.Use(logger.New(logger.Config{
		TimeZone: "asia/bangkok",
	}))

	app.Static("/", "./wwwroot")
	app.Get("/hello", hello)
	app.Post("/hello/:name/:surname", postHello)
	app.Post("/hello/:id", postHelloId)
	app.Get("/query", func(c *fiber.Ctx) error {
		name := c.Query("name")
		return c.SendString("name " + name)
	})

	app.Get("/query2", func(c *fiber.Ctx) error {
		person := Person{}
		c.QueryParser(&person)
		return c.JSON(person)
	})

	app.Get("/wildcard/*", func(c *fiber.Ctx) error {
		wildcard := c.Params("*")
		return c.SendString(wildcard)
	})

	app.Listen(":8080")
}

func hello(c *fiber.Ctx) error {
	return c.SendString("Hello")
}

func postHello(c *fiber.Ctx) error {
	name := c.Params("name")
	surname := c.Params("surname")
	return c.SendString("name " + name + ", surname " + surname)
}

func postHelloId(c *fiber.Ctx) error {
	id, err := c.ParamsInt("id")
	if err != nil {
		return fiber.ErrBadRequest
	}
	return c.SendString(fmt.Sprintf("ID = %v", id))
}

type Person struct {
	Id   int    `json:"id"`
	Name string `json:"name"`
}
